package apply

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/BurntSushi/toml"

	"quadmatic/internal/config"
	"quadmatic/internal/gitops"
	"quadmatic/internal/manifest"
	"quadmatic/internal/netmgr"
	"quadmatic/internal/quadlet"
	"quadmatic/internal/secrets"
	"quadmatic/internal/state"
	"quadmatic/pkg/users"
)

const (
	defaultStartVerifyTimeout = 30 * time.Second
	defaultDHCPTimeout        = 30 * time.Second
	maxVerifyPollInterval     = 250 * time.Millisecond
	minVerifyPollInterval     = 5 * time.Millisecond
)

// GitClient abstracts Git repository fetch, verification, commit export, and commit file reads.
type GitClient interface {
	FetchAndVerify(ctx context.Context, appliedSHA string, allowNonFF bool) (string, error)
	VerifyLocalRepo(ctx context.Context, repoPath, appliedSHA string, allowNonFF, noVerify bool) (string, error)
	ExportCommit(ctx context.Context, sha, destDir string) error
	ReadFileAtCommit(ctx context.Context, sha, relPath string) ([]byte, error)
}

// UsersReconciler abstracts service-user planning and reconciliation.
type UsersReconciler interface {
	Plan(ctx context.Context, reg *users.Registry, activeUsers []string, previouslyManaged []string) (*users.Plan, error)
	Apply(ctx context.Context, reg *users.Registry, activeUsers []string, previouslyManaged []string) (*users.Plan, error)
}

// QuadletValidator abstracts `quadlet --dryrun` validation and unit generation.
type QuadletValidator interface {
	ValidateHost(ctx context.Context, host *manifest.RenderedHost) (map[string]quadlet.GeneratedUnit, error)
}

// SecretsManager abstracts Podman secret creation/replacement and removal.
type SecretsManager interface {
	Upsert(ctx context.Context, scope, name string, plaintext []byte) error
	Remove(ctx context.Context, scope, name string) error
}

// NetmgrReconciler abstracts NetworkManager VLAN/VRF/macvlan reconciliation, drift detection,
// nftables outbound_guard application, and transactional snapshot/restore.
type NetmgrReconciler interface {
	CheckKernelInvariants() error
	ResolveVLANParents(ctx context.Context, host *manifest.ResolvedHost) (map[int]string, error)
	ReadLiveDNS(ctx context.Context, ifname string) ([]string, error)
	Snapshot(ctx context.Context, owned []state.ManagedNetworkRecord) (*netmgr.Snapshot, error)
	DetectDrift(ctx context.Context, host *manifest.ResolvedHost, owned []state.ManagedNetworkRecord) (bool, error)
	ApplyProfiles(ctx context.Context, host *manifest.ResolvedHost, prevOwned []state.ManagedNetworkRecord, dhcpTimeout time.Duration) ([]state.ManagedNetworkRecord, map[string][]string, error)
	ApplyNFTables(ctx context.Context, host *manifest.ResolvedHost) (string, error)
	Restore(ctx context.Context, snap *netmgr.Snapshot, createdDuringAttempt []state.ManagedNetworkRecord) error
}

// ReconcileOptions configures a single reconcile pass.
type ReconcileOptions struct {
	DryRun             bool
	AllowNonFF         bool
	LocalRepoPath      string
	NoVerify           bool
	StartVerifyTimeout time.Duration
}

// UnitStatus reports a managed unit whose systemd ActiveState is not "active".
type UnitStatus struct {
	Scope       string
	Unit        string
	ActiveState string
}

// Result summarizes the outcome, drift, rollbacks, unit counts, and timing of Reconcile.
type Result struct {
	AppliedSHA           string
	PlanSummary          string
	DriftDetected        bool
	RolledBack           bool
	FailedStage          string
	ManagedUnitsRootless int
	ManagedUnitsRootful  int
	FailedUnits          []UnitStatus
	Duration             time.Duration
}

// EngineDeps provides dependencies and optional test overrides for Engine.
type EngineDeps struct {
	Config             *config.HostConfig
	Git                GitClient
	Users              UsersReconciler
	Quadlet            QuadletValidator
	Secrets            SecretsManager
	Netmgr             NetmgrReconciler
	Systemd            Systemd
	Logger             *slog.Logger
	RootDir            string
	Chown              func(path string, uid, gid int) error
	DHCPTimeout        time.Duration
	VerifyPollInterval time.Duration
}

// Engine executes the 8-stage transactional reconcile loop.
type Engine struct {
	cfg                *config.HostConfig
	git                GitClient
	users              UsersReconciler
	quadlet            QuadletValidator
	secrets            SecretsManager
	netmgr             NetmgrReconciler
	systemd            Systemd
	logger             *slog.Logger
	rootDir            string
	chown              func(path string, uid, gid int) error
	dhcpTimeout        time.Duration
	verifyPollInterval time.Duration
}

// NewEngine constructs a reconcile Engine with sensible defaults for nil optional dependencies.
func NewEngine(deps EngineDeps) *Engine {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	gitClient := deps.Git
	if gitClient == nil && deps.Config != nil {
		gitClient = gitops.NewClient(deps.Config)
	}

	usersRec := deps.Users
	if usersRec == nil {
		usersRec = users.NewReconciler(users.Options{})
	}

	quadletVal := deps.Quadlet
	if quadletVal == nil {
		quadletVal = quadlet.NewValidator("", nil)
	}

	secretsMgr := deps.Secrets
	if secretsMgr == nil {
		secretsMgr = secrets.NewManager(nil)
	}

	netRec := deps.Netmgr
	if netRec == nil && deps.Config != nil {
		netRec = netmgr.NewReconciler(deps.Config.TrunkInterface, nil, nil)
	}

	sysd := deps.Systemd
	if sysd == nil {
		sysd = NewSystemctl(nil)
	}

	chownFn := deps.Chown
	if chownFn == nil {
		if deps.RootDir == "" {
			chownFn = os.Chown
		} else {
			chownFn = func(string, int, int) error { return nil }
		}
	}

	dhcpTimeout := deps.DHCPTimeout
	if dhcpTimeout <= 0 {
		dhcpTimeout = defaultDHCPTimeout
	}

	return &Engine{
		cfg:                deps.Config,
		git:                gitClient,
		users:              usersRec,
		quadlet:            quadletVal,
		secrets:            secretsMgr,
		netmgr:             netRec,
		systemd:            sysd,
		logger:             logger,
		rootDir:            deps.RootDir,
		chown:              chownFn,
		dhcpTimeout:        dhcpTimeout,
		verifyPollInterval: deps.VerifyPollInterval,
	}
}

type unitID struct {
	Scope    string
	UnitName string
	Key      string
	IsHelper bool
}

type desiredSecret struct {
	Key       string
	Scope     string
	Name      string
	RelPath   string
	Plaintext []byte
	Digest    string
}

type unitPlanMeta struct {
	ID             unitID
	Unit           quadlet.GeneratedUnit
	Component      string
	SourceDestPath string
	DataDir        string
	OwnerUID       int
}

type applyPlan struct {
	desiredFiles       map[string]manifest.RenderedFile
	fileCompScope      map[string]string
	fileChownRoots     map[string]string
	desiredUnits       map[string]unitPlanMeta
	filesToWrite       []string
	filesToPrune       []string
	healedFiles        map[string]bool
	secretsToUpsert    []string
	secretsToPrune     []string
	changedSecretKeys  map[string]bool
	unitsToStart       []unitID
	unitsToRestart     []unitID
	unitsToStop        []unitID
	affectedScopes     map[string]bool
	driftDetected      bool
	managedRootless    int
	managedRootful     int
	compByFileDestPath map[string]string
}

type rollbackTracker struct {
	createdOrMutatedNet []state.ManagedNetworkRecord
	writtenFiles        []string
	prunedFiles         []string
	upsertedSecrets     map[string]secretRef
	prunedSecrets       map[string]secretRef
	addedUnits          []unitID
	restartedUnits      []unitID
	stoppedUnits        []unitID
	affectedScopes      map[string]bool
	daemonReloaded      map[string]bool
}

type secretRef struct {
	Scope string
	Name  string
}

// Reconcile executes the full 8-stage transactional reconciliation loop.
func (e *Engine) Reconcile(ctx context.Context, opts ReconcileOptions) (*Result, error) {
	startTime := time.Now()
	res := &Result{}
	defer func() {
		res.Duration = time.Since(startTime)
	}()

	if e == nil || e.cfg == nil {
		res.FailedStage = "validate"
		return res, errors.New("reconcile engine or host config is nil")
	}
	if e.git == nil || e.users == nil || e.quadlet == nil || e.secrets == nil || e.netmgr == nil || e.systemd == nil {
		res.FailedStage = "validate"
		return res, errors.New("reconcile engine has nil dependency")
	}
	if err := ctx.Err(); err != nil {
		res.FailedStage = "fetch"
		return res, err
	}

	prevState, err := state.Load(e.cfg.StateFile)
	if err != nil {
		res.FailedStage = "fetch"
		return res, fmt.Errorf("load state %q: %w", e.cfg.StateFile, err)
	}
	res.AppliedSHA = prevState.AppliedSHA

	// Stage 1: Fetch & Verify
	var newSHA string
	if opts.LocalRepoPath != "" {
		newSHA, err = e.git.VerifyLocalRepo(ctx, opts.LocalRepoPath, prevState.AppliedSHA, opts.AllowNonFF, opts.NoVerify)
	} else {
		newSHA, err = e.git.FetchAndVerify(ctx, prevState.AppliedSHA, opts.AllowNonFF)
	}
	if err != nil {
		res.FailedStage = classifyGitStage(err, opts.LocalRepoPath != "")
		return res, err
	}

	exportDir, err := os.MkdirTemp("", "quadmatic-export-*")
	if err != nil {
		res.FailedStage = "fetch"
		return res, fmt.Errorf("create export temp dir: %w", err)
	}
	defer os.RemoveAll(exportDir)

	if err := e.git.ExportCommit(ctx, newSHA, exportDir); err != nil {
		res.FailedStage = "fetch"
		return res, err
	}

	// Stage 2: Load & Resolve
	reg, err := users.LoadRegistry(filepath.Join(exportDir, "users.toml"))
	if err != nil {
		res.FailedStage = "validate"
		return res, err
	}
	resolved, err := manifest.LoadHost(exportDir, e.cfg.Hostname, reg)
	if err != nil {
		res.FailedStage = "validate"
		return res, err
	}

	// Stage 3: Static Validation (zero host mutations)
	if err := manifest.Validate(resolved, exportDir); err != nil {
		res.FailedStage = "validate"
		return res, err
	}

	activeUsers := collectActiveUsers(resolved)
	userPlan, err := e.users.Plan(ctx, reg, activeUsers, prevState.ManagedUsers)
	if err != nil {
		res.FailedStage = "validate"
		return res, err
	}

	if hasRootlessNetwork(resolved) {
		if err := e.netmgr.CheckKernelInvariants(); err != nil {
			res.FailedStage = "validate"
			return res, err
		}
	}

	parentIfaces, err := e.netmgr.ResolveVLANParents(ctx, resolved)
	if err != nil {
		res.FailedStage = "validate"
		return res, err
	}

	desiredSecrets, identities, err := e.prepareSecrets(exportDir, resolved, prevState)
	if err != nil {
		res.FailedStage = "validate"
		return res, err
	}
	defer clearDesiredSecrets(desiredSecrets)

	stage3LiveDNS := e.readExistingLiveDNS(ctx, resolved)
	rendered, err := manifest.RenderHost(resolved, manifest.RenderEnv{
		LiveDNS:      stage3LiveDNS,
		ParentIfaces: parentIfaces,
		DryRun:       true,
	})
	if err != nil {
		res.FailedStage = "validate"
		return res, err
	}

	desiredUnits, err := e.quadlet.ValidateHost(ctx, rendered)
	if err != nil {
		res.FailedStage = "validate"
		return res, err
	}

	// Stage 4: Plan & Drift Detection
	plan, err := e.buildApplyPlan(rendered, desiredUnits, desiredSecrets, prevState)
	if err != nil {
		res.FailedStage = "validate"
		return res, err
	}

	netDrifted, err := e.netmgr.DetectDrift(ctx, resolved, prevState.Networks)
	if err != nil {
		res.FailedStage = "validate"
		return res, err
	}
	if netDrifted {
		plan.driftDetected = true
	}

	res.DriftDetected = plan.driftDetected
	res.ManagedUnitsRootless = plan.managedRootless
	res.ManagedUnitsRootful = plan.managedRootful

	stage4FailedUnits, err := e.queryExistingUnitStates(ctx, prevState, plan.desiredUnits)
	if err != nil {
		res.FailedStage = "apply"
		return res, err
	}

	res.PlanSummary = formatPlanSummary(prevState.AppliedSHA, newSHA, rendered, userPlan, plan, netDrifted, stage4FailedUnits)

	if opts.DryRun {
		res.FailedUnits = stage4FailedUnits
		return res, nil
	}

	hasUserWork := hasMutatingUserAction(userPlan)
	needsMutate := newSHA != prevState.AppliedSHA ||
		plan.driftDetected ||
		netDrifted ||
		rendered.UsedPlaceholderDNS ||
		hasUserWork ||
		len(plan.filesToWrite) > 0 ||
		len(plan.filesToPrune) > 0 ||
		len(plan.secretsToUpsert) > 0 ||
		len(plan.secretsToPrune) > 0 ||
		len(plan.unitsToStart) > 0 ||
		len(plan.unitsToRestart) > 0 ||
		len(plan.unitsToStop) > 0

	if !needsMutate {
		res.AppliedSHA = newSHA
		res.FailedUnits = stage4FailedUnits
		return res, nil
	}

	// Stage 5: Users (non-destructive; users are never deleted on rollback)
	if _, err := e.users.Apply(ctx, reg, activeUsers, prevState.ManagedUsers); err != nil {
		res.FailedStage = "users"
		return res, err
	}
	managedUsers := unionSortedStrings(prevState.ManagedUsers, activeUsers)

	// Stage 6: Pre-Apply Rollback Snapshot
	fileSnap, err := captureFileSnapshot(e.rootDir, prevState.Files, plan.desiredFiles)
	if err != nil {
		res.FailedStage = "files"
		return res, fmt.Errorf("capture file snapshot: %w", err)
	}
	netSnap, err := e.netmgr.Snapshot(ctx, prevState.Networks)
	if err != nil {
		res.FailedStage = "net"
		return res, fmt.Errorf("capture network snapshot: %w", err)
	}

	tracker := &rollbackTracker{
		upsertedSecrets: make(map[string]secretRef),
		prunedSecrets:   make(map[string]secretRef),
		affectedScopes:  make(map[string]bool),
		daemonReloaded:  make(map[string]bool),
	}

	runRollback := func(failedStage string, cause error) (*Result, error) {
		rbErr := e.rollback(ctx, prevState, fileSnap, netSnap, tracker, identities, plan)
		res.AppliedSHA = prevState.AppliedSHA
		res.RolledBack = true
		if rbErr != nil {
			res.FailedStage = "rollback"
			e.logger.Error("reconcile rollback failed", "failed_stage", failedStage, "cause", cause, "rollback_err", rbErr)
			return res, fmt.Errorf("%s failed (%w); rollback failed: %v", failedStage, cause, rbErr)
		}
		res.FailedStage = failedStage
		e.logger.Error("reconcile rolled back", "failed_stage", failedStage, "cause", cause, "restored_sha", prevState.AppliedSHA)
		return res, cause
	}

	// Stage 7a: Networks & Post-DHCP Re-Render
	newNetRecords, postApplyLiveDNS, err := e.netmgr.ApplyProfiles(ctx, resolved, prevState.Networks, e.dhcpTimeout)
	tracker.createdOrMutatedNet = newNetRecords
	if err != nil {
		return runRollback("net", err)
	}

	finalLiveDNS := cloneStringSliceMap(stage3LiveDNS)
	for compName, dns := range postApplyLiveDNS {
		finalLiveDNS[compName] = slices.Clone(dns)
	}

	if rendered.UsedPlaceholderDNS || !stringSliceMapsEqual(stage3LiveDNS, finalLiveDNS) {
		rendered, err = manifest.RenderHost(resolved, manifest.RenderEnv{
			LiveDNS:      finalLiveDNS,
			ParentIfaces: parentIfaces,
			DryRun:       false,
		})
		if err != nil {
			return runRollback("net", fmt.Errorf("post-DHCP render failed: %w", err))
		}
		desiredUnits, err = e.quadlet.ValidateHost(ctx, rendered)
		if err != nil {
			return runRollback("net", fmt.Errorf("post-DHCP quadlet validation failed: %w", err))
		}
		savedDrift := plan.driftDetected
		savedHealed := plan.healedFiles
		plan, err = e.buildApplyPlan(rendered, desiredUnits, desiredSecrets, prevState)
		if err != nil {
			return runRollback("net", fmt.Errorf("post-DHCP plan rebuild failed: %w", err))
		}
		if savedDrift {
			plan.driftDetected = true
		}
		for k, v := range savedHealed {
			if v {
				plan.healedFiles[k] = true
			}
		}
		res.DriftDetected = plan.driftDetected
		res.ManagedUnitsRootless = plan.managedRootless
		res.ManagedUnitsRootful = plan.managedRootful
	}

	// Stage 7b: Atomic File Writes
	for _, destPath := range plan.filesToWrite {
		rf := plan.desiredFiles[destPath]
		absPath, err := resolveHostPath(e.rootDir, destPath)
		if err != nil {
			return runRollback("files", err)
		}
		var chownRootAbs string
		if rf.Kind == manifest.FileKindData && (rf.OwnerUID != 0 || rf.OwnerGID != 0) {
			if cr := plan.fileChownRoots[destPath]; cr != "" {
				chownRootAbs, err = resolveHostPath(e.rootDir, cr)
				if err != nil {
					return runRollback("files", err)
				}
			}
		}
		if err := writeFileAtomic(absPath, rf.Content, rf.Mode, rf.OwnerUID, rf.OwnerGID, chownRootAbs, e.chown); err != nil {
			return runRollback("files", err)
		}
		tracker.writtenFiles = append(tracker.writtenFiles, destPath)
		if rf.Kind == manifest.FileKindQuadlet {
			if scope := plan.fileCompScope[destPath]; scope != "" {
				tracker.affectedScopes[scope] = true
			}
		}
	}

	// Stage 7c: Podman Secrets Upsert
	for _, key := range plan.secretsToUpsert {
		sec := desiredSecrets[key]
		if err := e.secrets.Upsert(ctx, sec.Scope, sec.Name, sec.Plaintext); err != nil {
			return runRollback("secrets", err)
		}
		tracker.upsertedSecrets[key] = secretRef{Scope: sec.Scope, Name: sec.Name}
	}

	// Stage 7d: Prune, DaemonReload, Start/Restart, Verify Active, ApplyNFTables
	for _, u := range plan.unitsToStop {
		if err := e.systemd.Stop(ctx, u.Scope, u.UnitName); err != nil {
			return runRollback("apply", err)
		}
		tracker.stoppedUnits = append(tracker.stoppedUnits, u)
		tracker.affectedScopes[u.Scope] = true
	}

	for _, destPath := range plan.filesToPrune {
		absPath, err := resolveHostPath(e.rootDir, destPath)
		if err != nil {
			return runRollback("apply", err)
		}
		if err := removeFileIfExists(absPath); err != nil {
			return runRollback("apply", err)
		}
		tracker.prunedFiles = append(tracker.prunedFiles, destPath)
		if prevRec, ok := prevState.Files[destPath]; ok && prevRec.Kind == manifest.FileKindQuadlet {
			if scope := scopeFromFilePath(destPath, prevState, resolved); scope != "" {
				tracker.affectedScopes[scope] = true
			}
		}
	}

	for _, key := range plan.secretsToPrune {
		scope, name, ok := strings.Cut(key, "/")
		if !ok {
			return runRollback("apply", fmt.Errorf("malformed state secret key %q", key))
		}
		if err := e.secrets.Remove(ctx, scope, name); err != nil {
			return runRollback("apply", err)
		}
		tracker.prunedSecrets[key] = secretRef{Scope: scope, Name: name}
	}

	for _, scope := range sortedBoolKeys(tracker.affectedScopes) {
		if err := e.systemd.DaemonReload(ctx, scope); err != nil {
			return runRollback("apply", err)
		}
		tracker.daemonReloaded[scope] = true
	}

	for _, u := range plan.unitsToStart {
		tracker.addedUnits = append(tracker.addedUnits, u)
		if err := e.systemd.Start(ctx, u.Scope, u.UnitName); err != nil {
			return runRollback("apply", err)
		}
	}

	for _, u := range plan.unitsToRestart {
		tracker.restartedUnits = append(tracker.restartedUnits, u)
		if err := e.systemd.Restart(ctx, u.Scope, u.UnitName); err != nil {
			return runRollback("apply", err)
		}
	}

	verifyTimeout := opts.StartVerifyTimeout
	if verifyTimeout <= 0 {
		verifyTimeout = defaultStartVerifyTimeout
	}
	toVerify := make([]unitID, 0, len(plan.unitsToStart)+len(plan.unitsToRestart))
	toVerify = append(toVerify, plan.unitsToStart...)
	toVerify = append(toVerify, plan.unitsToRestart...)
	for _, u := range toVerify {
		if err := e.verifyUnitActive(ctx, u, verifyTimeout); err != nil {
			return runRollback("apply", err)
		}
	}

	nftHash, err := e.netmgr.ApplyNFTables(ctx, resolved)
	if err != nil {
		return runRollback("net", err)
	}

	// Stage 8: Commit State
	newState := buildNextState(newSHA, managedUsers, plan, desiredSecrets, newNetRecords, nftHash)
	if err := state.SaveAtomic(e.cfg.StateFile, newState); err != nil {
		return runRollback("apply", fmt.Errorf("commit state %q: %w", e.cfg.StateFile, err))
	}

	verifiedSet := make(map[string]bool, len(toVerify))
	for _, u := range toVerify {
		verifiedSet[u.Key] = true
	}
	var finalFailed []UnitStatus
	for _, st := range stage4FailedUnits {
		key := st.Scope + "/" + st.Unit
		if verifiedSet[key] {
			continue
		}
		if _, exists := plan.desiredUnits[key]; exists {
			finalFailed = append(finalFailed, st)
		}
	}

	res.AppliedSHA = newSHA
	res.FailedUnits = finalFailed
	return res, nil
}

func (e *Engine) rollback(
	ctx context.Context,
	prevState *state.State,
	fileSnap *fileSnapshot,
	netSnap *netmgr.Snapshot,
	tracker *rollbackTracker,
	identities []age.Identity,
	plan *applyPlan,
) error {
	var errs []error

	// 1. Stop units newly added in this attempt (reverse order so workloads stop before helper units).
	for i := len(tracker.addedUnits) - 1; i >= 0; i-- {
		u := tracker.addedUnits[i]
		if err := e.systemd.Stop(ctx, u.Scope, u.UnitName); err != nil {
			errs = append(errs, fmt.Errorf("stop added unit %s: %w", u.Key, err))
		}
	}

	// 2. Restore snapshotted files and remove newly created files.
	mutatedFiles := make(map[string]bool, len(tracker.writtenFiles)+len(tracker.prunedFiles))
	for _, p := range tracker.writtenFiles {
		mutatedFiles[p] = true
	}
	for _, p := range tracker.prunedFiles {
		mutatedFiles[p] = true
	}
	for _, destPath := range sortedBoolKeys(mutatedFiles) {
		absPath, err := resolveHostPath(e.rootDir, destPath)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		entry, ok := fileSnap.entries[destPath]
		if !ok || !entry.Existed {
			if err := removeFileIfExists(absPath); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		var chownRootAbs string
		if entry.OwnerUID != 0 || entry.OwnerGID != 0 {
			if cr := inferUserHomeRoot(destPath); cr != "" {
				chownRootAbs, _ = resolveHostPath(e.rootDir, cr)
			}
		}
		if err := writeFileAtomic(absPath, entry.Content, entry.Mode, entry.OwnerUID, entry.OwnerGID, chownRootAbs, e.chown); err != nil {
			errs = append(errs, fmt.Errorf("restore file %q: %w", destPath, err))
		}
	}

	// 3. Restore NetworkManager profiles and nftables ruleset.
	if err := e.netmgr.Restore(ctx, netSnap, tracker.createdOrMutatedNet); err != nil {
		errs = append(errs, fmt.Errorf("restore network state: %w", err))
	}

	// 4. Restore modified/pruned Podman secrets from prevState.AppliedSHA and remove newly created ones.
	secretsToRestore := make(map[string]secretRef)
	for key, ref := range tracker.upsertedSecrets {
		if _, existed := prevState.Secrets[key]; existed {
			secretsToRestore[key] = ref
		} else {
			if err := e.secrets.Remove(ctx, ref.Scope, ref.Name); err != nil {
				errs = append(errs, fmt.Errorf("remove added secret %s: %w", key, err))
			}
		}
	}
	for key, ref := range tracker.prunedSecrets {
		secretsToRestore[key] = ref
	}

	if len(secretsToRestore) > 0 && prevState.AppliedSHA != "" {
		if err := e.restoreSecretsFromCommit(ctx, prevState.AppliedSHA, secretsToRestore, identities); err != nil {
			errs = append(errs, err)
		}
	}

	// 5. Run daemon-reload on affected scopes and restart previously active units whose restored state differs.
	for _, scope := range sortedBoolKeys(tracker.affectedScopes) {
		if err := e.systemd.DaemonReload(ctx, scope); err != nil {
			errs = append(errs, fmt.Errorf("daemon-reload scope %q: %w", scope, err))
		}
	}

	unitsToRestart := collectRollbackRestarts(prevState, tracker, plan, mutatedFiles)
	for _, u := range unitsToRestart {
		if err := e.systemd.Restart(ctx, u.Scope, u.UnitName); err != nil {
			errs = append(errs, fmt.Errorf("restart restored unit %s: %w", u.Key, err))
		}
	}

	return errors.Join(errs...)
}

func (e *Engine) restoreSecretsFromCommit(
	ctx context.Context,
	appliedSHA string,
	toRestore map[string]secretRef,
	identities []age.Identity,
) error {
	if len(identities) == 0 {
		if e.cfg.AgeIdentity == "" {
			return errors.New("age_identity is required to restore secrets during rollback")
		}
		var err error
		identities, err = secrets.LoadIdentities(e.cfg.AgeIdentity)
		if err != nil {
			return fmt.Errorf("load age identity for rollback: %w", err)
		}
	}

	hostBytes, err := e.git.ReadFileAtCommit(ctx, appliedSHA, "hosts/"+e.cfg.Hostname+".toml")
	if err != nil {
		return fmt.Errorf("read host manifest at %s for secret rollback: %w", appliedSHA, err)
	}
	var rawHost struct {
		Components []struct {
			Name    string `toml:"name"`
			User    string `toml:"user"`
			Rootful bool   `toml:"rootful"`
		} `toml:"component"`
	}
	if _, err := toml.Decode(string(hostBytes), &rawHost); err != nil {
		return fmt.Errorf("decode host manifest at %s: %w", appliedSHA, err)
	}

	secretRelPaths := make(map[string]string, len(toRestore))
	for _, comp := range rawHost.Components {
		scope := comp.User
		if comp.Rootful {
			scope = RootfulScope
		}
		compTOML, err := e.git.ReadFileAtCommit(ctx, appliedSHA, "components/"+comp.Name+"/component.toml")
		if err != nil {
			continue
		}
		var rawComp struct {
			Secrets map[string]string `toml:"secrets"`
		}
		if _, err := toml.Decode(string(compTOML), &rawComp); err != nil {
			return fmt.Errorf("decode component %q manifest at %s: %w", comp.Name, appliedSHA, err)
		}
		for secName, relPath := range rawComp.Secrets {
			secretRelPaths[scope+"/"+secName] = relPath
		}
	}

	var errs []error
	keys := make([]string, 0, len(toRestore))
	for k := range toRestore {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		ref := toRestore[key]
		relPath, ok := secretRelPaths[key]
		if !ok {
			errs = append(errs, fmt.Errorf("could not locate .age source path for secret %s at commit %s", key, appliedSHA))
			continue
		}
		ct, err := e.git.ReadFileAtCommit(ctx, appliedSHA, relPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("read secret %s (%s) at commit %s: %w", key, relPath, appliedSHA, err))
			continue
		}
		pt, err := secrets.Decrypt(ct, identities)
		if err != nil {
			errs = append(errs, fmt.Errorf("decrypt secret %s (%s) at commit %s: %w", key, relPath, appliedSHA, err))
			continue
		}
		upsertErr := e.secrets.Upsert(ctx, ref.Scope, ref.Name, pt)
		clear(pt)
		if upsertErr != nil {
			errs = append(errs, fmt.Errorf("restore secret %s: %w", key, upsertErr))
		}
	}
	return errors.Join(errs...)
}

func collectRollbackRestarts(
	prevState *state.State,
	tracker *rollbackTracker,
	plan *applyPlan,
	mutatedFiles map[string]bool,
) []unitID {
	if prevState.AppliedSHA == "" || len(prevState.GeneratedUnits) == 0 {
		return nil
	}

	restartSet := make(map[string]unitID)
	addUnit := func(u unitID) {
		if _, existed := prevState.GeneratedUnits[u.Key]; existed {
			restartSet[u.Key] = u
		}
	}

	for _, u := range tracker.stoppedUnits {
		addUnit(u)
	}
	for _, u := range tracker.restartedUnits {
		addUnit(u)
	}

	// Also catch any existing unit in prevState whose files were mutated and whose scope was reloaded.
	mutatedComps := make(map[string]bool)
	for destPath := range mutatedFiles {
		if rec, ok := prevState.Files[destPath]; ok && rec.Component != "" {
			mutatedComps[rec.Component] = true
		}
		if comp, ok := plan.compByFileDestPath[destPath]; ok && comp != "" {
			mutatedComps[comp] = true
		}
	}
	for unitKey, meta := range plan.desiredUnits {
		if _, existed := prevState.GeneratedUnits[unitKey]; !existed {
			continue
		}
		if !tracker.daemonReloaded[meta.ID.Scope] && !tracker.affectedScopes[meta.ID.Scope] {
			continue
		}
		if mutatedFiles[meta.SourceDestPath] || (!meta.ID.IsHelper && mutatedComps[meta.Component]) {
			addUnit(meta.ID)
		}
	}

	out := make([]unitID, 0, len(restartSet))
	for _, u := range restartSet {
		out = append(out, u)
	}
	sortUnitIDs(out, false)
	return out
}

func (e *Engine) verifyUnitActive(ctx context.Context, u unitID, timeout time.Duration) error {
	interval := e.verifyPollInterval
	if interval <= 0 {
		interval = timeout / 10
		if interval > maxVerifyPollInterval {
			interval = maxVerifyPollInterval
		}
		if interval < minVerifyPollInterval {
			interval = minVerifyPollInterval
		}
	}

	deadline := time.Now().Add(timeout)
	for {
		st, err := e.systemd.ActiveState(ctx, u.Scope, u.UnitName)
		if err != nil {
			return fmt.Errorf("check active state of %s: %w", u.Key, err)
		}
		switch st {
		case "active":
			return nil
		case "failed":
			return fmt.Errorf("unit %s entered failed state", u.Key)
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("timed out waiting for unit %s to become active (last state: %q)", u.Key, st)
		}
		waitFor := interval
		if remaining < waitFor {
			waitFor = remaining
		}
		timer := time.NewTimer(waitFor)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (e *Engine) prepareSecrets(
	exportDir string,
	resolved *manifest.ResolvedHost,
	prevState *state.State,
) (map[string]desiredSecret, []age.Identity, error) {
	desired := make(map[string]desiredSecret)
	needIdentities := prevState.AppliedSHA != "" && len(prevState.Secrets) > 0
	for _, comp := range resolved.Components {
		if len(comp.Secrets) > 0 {
			needIdentities = true
			break
		}
	}
	if !needIdentities {
		return desired, nil, nil
	}

	identities, err := secrets.LoadIdentities(e.cfg.AgeIdentity)
	if err != nil {
		return nil, nil, err
	}

	for _, comp := range resolved.Components {
		scope := comp.Scope()
		names := make([]string, 0, len(comp.Secrets))
		for n := range comp.Secrets {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, secName := range names {
			relPath := comp.Secrets[secName]
			key := scope + "/" + secName
			if existing, dup := desired[key]; dup {
				if existing.RelPath != relPath {
					clearDesiredSecrets(desired)
					return nil, nil, fmt.Errorf("conflicting paths for secret %q in scope %q: %q vs %q", secName, scope, existing.RelPath, relPath)
				}
				continue
			}

			ct, err := os.ReadFile(filepath.Join(exportDir, filepath.FromSlash(relPath)))
			if err != nil {
				clearDesiredSecrets(desired)
				return nil, nil, fmt.Errorf("read secret %q (%s): %w", key, relPath, err)
			}
			pt, err := secrets.Decrypt(ct, identities)
			if err != nil {
				clearDesiredSecrets(desired)
				return nil, nil, fmt.Errorf("decrypt secret %q (%s): %w", key, relPath, err)
			}
			desired[key] = desiredSecret{
				Key:       key,
				Scope:     scope,
				Name:      secName,
				RelPath:   relPath,
				Plaintext: pt,
				Digest:    secrets.Digest(pt),
			}
		}
	}
	return desired, identities, nil
}

func clearDesiredSecrets(m map[string]desiredSecret) {
	for _, sec := range m {
		clear(sec.Plaintext)
	}
}

func (e *Engine) readExistingLiveDNS(ctx context.Context, resolved *manifest.ResolvedHost) map[string][]string {
	out := make(map[string][]string)
	for _, comp := range resolved.Components {
		if comp.Rootful || comp.Network == nil || !comp.Network.DNSFromDHCP {
			continue
		}
		ifname := fmt.Sprintf("qm-%d", comp.UID)
		dns, err := e.netmgr.ReadLiveDNS(ctx, ifname)
		if err == nil && len(dns) > 0 {
			out[comp.Name] = dns
		}
	}
	return out
}

func (e *Engine) buildApplyPlan(
	rendered *manifest.RenderedHost,
	generatedUnits map[string]quadlet.GeneratedUnit,
	desiredSecrets map[string]desiredSecret,
	prevState *state.State,
) (*applyPlan, error) {
	p := &applyPlan{
		desiredFiles:       make(map[string]manifest.RenderedFile),
		fileCompScope:      make(map[string]string),
		fileChownRoots:     make(map[string]string),
		desiredUnits:       make(map[string]unitPlanMeta, len(generatedUnits)),
		healedFiles:        make(map[string]bool),
		changedSecretKeys:  make(map[string]bool),
		affectedScopes:     make(map[string]bool),
		compByFileDestPath: make(map[string]string),
	}

	compScope := make(map[string]string, len(rendered.Components))
	compDataPaths := make(map[string][]string, len(rendered.Components))
	compFileComps := make(map[string]string)
	quadletLookup := make(map[string]struct {
		compName string
		destPath string
	})
	scopeCompNames := make(map[string][]string)

	for _, comp := range rendered.Components {
		scope := comp.Scope()
		compScope[comp.Name] = scope
		scopeCompNames[scope] = append(scopeCompNames[scope], comp.Name)
		userHomeRoot := ""
		if !comp.Rootful && comp.User != "" {
			userHomeRoot = path.Join("/var/home", comp.User)
		}
		for _, rf := range comp.Files {
			p.desiredFiles[rf.DestPath] = rf
			p.fileCompScope[rf.DestPath] = scope
			compFileComps[rf.DestPath] = comp.Name
			p.compByFileDestPath[rf.DestPath] = comp.Name
			if rf.Kind == manifest.FileKindQuadlet {
				quadletLookup[scope+"/"+rf.RelPath] = struct {
					compName string
					destPath string
				}{compName: comp.Name, destPath: rf.DestPath}
			} else {
				compDataPaths[comp.Name] = append(compDataPaths[comp.Name], rf.DestPath)
				if userHomeRoot != "" {
					p.fileChownRoots[rf.DestPath] = userHomeRoot
				}
			}
		}
	}

	// Inspect disk files for drift and needed writes.
	fileNeedsWrite := make(map[string]bool)
	desiredPaths := make([]string, 0, len(p.desiredFiles))
	for destPath := range p.desiredFiles {
		desiredPaths = append(desiredPaths, destPath)
	}
	sort.Strings(desiredPaths)

	for _, destPath := range desiredPaths {
		rf := p.desiredFiles[destPath]
		absPath, err := resolveHostPath(e.rootDir, destPath)
		if err != nil {
			return nil, err
		}
		diskInfo, err := inspectDiskFile(absPath)
		if err != nil {
			return nil, err
		}

		prevRec, tracked := prevState.Files[destPath]
		if tracked {
			drifted := !diskInfo.Exists ||
				!diskInfo.Regular ||
				diskInfo.SHA256 != prevRec.SHA256 ||
				diskInfo.Mode != prevRec.Mode ||
				(e.rootDir == "" && (diskInfo.UID != prevRec.OwnerUID || diskInfo.GID != prevRec.OwnerGID))
			if drifted {
				p.driftDetected = true
				p.healedFiles[destPath] = true
			}
		}

		needsWrite := !diskInfo.Exists ||
			!diskInfo.Regular ||
			diskInfo.SHA256 != rf.SHA256 ||
			diskInfo.Mode != rf.Mode ||
			(e.rootDir == "" && (diskInfo.UID != rf.OwnerUID || diskInfo.GID != rf.OwnerGID))
		if needsWrite {
			fileNeedsWrite[destPath] = true
			p.filesToWrite = append(p.filesToWrite, destPath)
		}
	}

	for destPath := range prevState.Files {
		if _, ok := p.desiredFiles[destPath]; !ok {
			p.filesToPrune = append(p.filesToPrune, destPath)
			absPath, err := resolveHostPath(e.rootDir, destPath)
			if err != nil {
				return nil, err
			}
			diskInfo, err := inspectDiskFile(absPath)
			if err != nil {
				return nil, err
			}
			prevRec := prevState.Files[destPath]
			if !diskInfo.Exists || !diskInfo.Regular || diskInfo.SHA256 != prevRec.SHA256 {
				p.driftDetected = true
			}
		}
	}
	sort.Strings(p.filesToPrune)

	// Determine components with changed, newly added, removed, or healed data files.
	compDataChanged := make(map[string]bool)
	for destPath, rf := range p.desiredFiles {
		if rf.Kind != manifest.FileKindData {
			continue
		}
		compName := compFileComps[destPath]
		prevRec, existed := prevState.Files[destPath]
		if !existed || prevRec.SHA256 != rf.SHA256 || prevRec.Mode != rf.Mode || p.healedFiles[destPath] || fileNeedsWrite[destPath] {
			compDataChanged[compName] = true
		}
	}
	for _, destPath := range p.filesToPrune {
		if prevRec, ok := prevState.Files[destPath]; ok && prevRec.Kind == manifest.FileKindData && prevRec.Component != "" {
			compDataChanged[prevRec.Component] = true
		}
	}

	// Determine secret upserts and prunes.
	secretKeys := make([]string, 0, len(desiredSecrets))
	for k := range desiredSecrets {
		secretKeys = append(secretKeys, k)
	}
	sort.Strings(secretKeys)
	for _, key := range secretKeys {
		sec := desiredSecrets[key]
		if prevDigest, ok := prevState.Secrets[key]; !ok || prevDigest != sec.Digest {
			p.secretsToUpsert = append(p.secretsToUpsert, key)
			p.changedSecretKeys[key] = true
		}
	}
	for key := range prevState.Secrets {
		if _, ok := desiredSecrets[key]; !ok {
			p.secretsToPrune = append(p.secretsToPrune, key)
			p.changedSecretKeys[key] = true
		}
	}
	sort.Strings(p.secretsToPrune)

	// Correlate GeneratedUnits to owning components and source quadlets.
	for unitKey, gu := range generatedUnits {
		compName, srcDestPath := correlateUnitOwner(gu, quadletLookup, scopeCompNames)
		isHelper := isHelperQuadletUnit(gu.UnitName, srcDestPath)
		id := unitID{
			Scope:    gu.Scope,
			UnitName: gu.UnitName,
			Key:      unitKey,
			IsHelper: isHelper,
		}
		p.desiredUnits[unitKey] = unitPlanMeta{
			ID:             id,
			Unit:           gu,
			Component:      compName,
			SourceDestPath: srcDestPath,
		}
		if gu.Scope == RootfulScope {
			p.managedRootful++
		} else {
			p.managedRootless++
		}
	}

	for unitKey, meta := range p.desiredUnits {
		prevUnitSHA, existed := prevState.GeneratedUnits[unitKey]
		if !existed {
			p.unitsToStart = append(p.unitsToStart, meta.ID)
			continue
		}

		dirty := meta.Unit.SHA256 != prevUnitSHA
		if !dirty && meta.SourceDestPath != "" && (p.healedFiles[meta.SourceDestPath] || fileNeedsWrite[meta.SourceDestPath]) {
			dirty = true
		}
		if !dirty && !meta.ID.IsHelper && compDataChanged[meta.Component] {
			dirty = true
		}
		if !dirty {
			for _, secName := range meta.Unit.SecretRefs {
				if p.changedSecretKeys[meta.Unit.Scope+"/"+secName] {
					dirty = true
					break
				}
			}
		}
		if dirty {
			p.unitsToRestart = append(p.unitsToRestart, meta.ID)
		}
	}

	for unitKey := range prevState.GeneratedUnits {
		if _, ok := p.desiredUnits[unitKey]; !ok {
			scope, unitName, ok := strings.Cut(unitKey, "/")
			if !ok {
				continue
			}
			p.unitsToStop = append(p.unitsToStop, unitID{
				Scope:    scope,
				UnitName: unitName,
				Key:      unitKey,
				IsHelper: isHelperQuadletUnit(unitName, ""),
			})
		}
	}

	sortUnitIDs(p.unitsToStart, false)
	sortUnitIDs(p.unitsToRestart, false)
	sortUnitIDs(p.unitsToStop, true)

	return p, nil
}

func (e *Engine) queryExistingUnitStates(
	ctx context.Context,
	prevState *state.State,
	desiredUnits map[string]unitPlanMeta,
) ([]UnitStatus, error) {
	var keys []string
	for k := range desiredUnits {
		if _, existed := prevState.GeneratedUnits[k]; existed {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var failed []UnitStatus
	for _, k := range keys {
		meta := desiredUnits[k]
		st, err := e.systemd.ActiveState(ctx, meta.ID.Scope, meta.ID.UnitName)
		if err != nil {
			return nil, fmt.Errorf("query systemd state for %s: %w", k, err)
		}
		if st != "active" {
			failed = append(failed, UnitStatus{
				Scope:       meta.ID.Scope,
				Unit:        meta.ID.UnitName,
				ActiveState: st,
			})
		}
	}
	return failed, nil
}

func correlateUnitOwner(
	gu quadlet.GeneratedUnit,
	quadletLookup map[string]struct {
		compName string
		destPath string
	},
	scopeCompNames map[string][]string,
) (compName, srcDestPath string) {
	for _, rawLine := range strings.Split(gu.Content, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "SourcePath=") {
			base := path.Base(strings.TrimSpace(strings.TrimPrefix(line, "SourcePath=")))
			if hit, ok := quadletLookup[gu.Scope+"/"+base]; ok {
				return hit.compName, hit.destPath
			}
		}
	}

	for _, cand := range quadletCandidates(gu.UnitName) {
		if hit, ok := quadletLookup[gu.Scope+"/"+cand]; ok {
			return hit.compName, hit.destPath
		}
	}

	if comps := scopeCompNames[gu.Scope]; len(comps) == 1 {
		return comps[0], ""
	}
	return "", ""
}

func quadletCandidates(unitName string) []string {
	if !strings.HasSuffix(unitName, ".service") {
		return nil
	}
	stem := strings.TrimSuffix(unitName, ".service")
	suffixMap := []struct {
		unitSuffix string
		ext        string
	}{
		{"-volume", ".volume"},
		{"-network", ".network"},
		{"-pod", ".pod"},
		{"-image", ".image"},
		{"-kube", ".kube"},
		{"-build", ".build"},
	}
	for _, m := range suffixMap {
		if strings.HasSuffix(stem, m.unitSuffix) {
			return []string{strings.TrimSuffix(stem, m.unitSuffix) + m.ext}
		}
	}
	return []string{stem + ".container", stem + ".kube"}
}

func isHelperQuadletUnit(unitName, srcDestPath string) bool {
	if srcDestPath != "" {
		ext := path.Ext(srcDestPath)
		return ext == ".volume" || ext == ".network" || ext == ".image" || ext == ".build"
	}
	return strings.HasSuffix(unitName, "-volume.service") ||
		strings.HasSuffix(unitName, "-network.service") ||
		strings.HasSuffix(unitName, "-image.service") ||
		strings.HasSuffix(unitName, "-build.service")
}

func sortUnitIDs(units []unitID, reverseHelpers bool) {
	slices.SortFunc(units, func(a, b unitID) int {
		if a.IsHelper != b.IsHelper {
			if reverseHelpers {
				if a.IsHelper {
					return 1
				}
				return -1
			}
			if a.IsHelper {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Key, b.Key)
	})
}

func buildNextState(
	sha string,
	managedUsers []string,
	plan *applyPlan,
	desiredSecrets map[string]desiredSecret,
	networks []state.ManagedNetworkRecord,
	nftHash string,
) *state.State {
	st := state.NewEmpty()
	st.AppliedSHA = sha
	st.AppliedAt = time.Now().UTC()
	st.ManagedUsers = slices.Clone(managedUsers)
	if st.ManagedUsers == nil {
		st.ManagedUsers = []string{}
	}
	for destPath, rf := range plan.desiredFiles {
		st.Files[destPath] = state.FileRecord{
			SHA256:    rf.SHA256,
			Mode:      rf.Mode,
			OwnerUID:  rf.OwnerUID,
			OwnerGID:  rf.OwnerGID,
			Component: plan.compByFileDestPath[destPath],
			Kind:      rf.Kind,
		}
	}
	for unitKey, meta := range plan.desiredUnits {
		st.GeneratedUnits[unitKey] = meta.Unit.SHA256
	}
	for key, sec := range desiredSecrets {
		st.Secrets[key] = sec.Digest
	}
	if networks != nil {
		st.Networks = slices.Clone(networks)
	}
	st.NFTablesHash = nftHash
	return st
}

func formatPlanSummary(
	prevSHA, newSHA string,
	rendered *manifest.RenderedHost,
	userPlan *users.Plan,
	plan *applyPlan,
	netDrifted bool,
	failedUnits []UnitStatus,
) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host: %s | Target SHA: %s (applied: %s)\n", rendered.Hostname, newSHA, prevSHA)
	if rendered.UsedPlaceholderDNS {
		b.WriteString("Note: placeholder DNS (192.0.2.53) used for pending dns_from_dhcp interfaces during dry-run/validation\n")
	}

	compNames := make([]string, 0, len(rendered.Components))
	for _, c := range rendered.Components {
		compNames = append(compNames, c.Name)
	}
	fmt.Fprintf(&b, "Components (%d): %s\n", len(compNames), strings.Join(compNames, ", "))

	if userPlan != nil {
		for _, act := range userPlan.Actions {
			if act.Kind != users.AdoptUser {
				fmt.Fprintf(&b, "User action: %s %s (uid=%d)\n", act.Kind, act.User, act.UID)
			}
		}
		for _, w := range userPlan.Warnings {
			fmt.Fprintf(&b, "User warning: %s\n", w)
		}
	}

	fmt.Fprintf(&b, "Files: write=%d prune=%d healed=%d\n", len(plan.filesToWrite), len(plan.filesToPrune), len(plan.healedFiles))
	fmt.Fprintf(&b, "Secrets: upsert=%d prune=%d\n", len(plan.secretsToUpsert), len(plan.secretsToPrune))
	fmt.Fprintf(&b, "Units: start=%d restart=%d stop=%d (rootless=%d rootful=%d)\n",
		len(plan.unitsToStart), len(plan.unitsToRestart), len(plan.unitsToStop), plan.managedRootless, plan.managedRootful)
	fmt.Fprintf(&b, "Drift: files=%v network=%v\n", len(plan.healedFiles) > 0, netDrifted)

	if len(failedUnits) > 0 {
		parts := make([]string, 0, len(failedUnits))
		for _, fu := range failedUnits {
			parts = append(parts, fmt.Sprintf("%s/%s=%s", fu.Scope, fu.Unit, fu.ActiveState))
		}
		fmt.Fprintf(&b, "Unchanged non-active units: %s\n", strings.Join(parts, ", "))
	}
	return b.String()
}

func classifyGitStage(err error, isLocal bool) string {
	msg := err.Error()
	if strings.Contains(msg, "verify SSH commit signature") ||
		strings.Contains(msg, "non-fast-forward") ||
		strings.Contains(msg, "allowed_signers") {
		return "verify"
	}
	if isLocal {
		return "fetch"
	}
	return "fetch"
}

func collectActiveUsers(host *manifest.ResolvedHost) []string {
	seen := make(map[string]bool)
	var out []string
	for _, c := range host.Components {
		if c.Rootful || c.User == "" || seen[c.User] {
			continue
		}
		seen[c.User] = true
		out = append(out, c.User)
	}
	sort.Strings(out)
	return out
}

func hasRootlessNetwork(host *manifest.ResolvedHost) bool {
	for _, c := range host.Components {
		if !c.Rootful && c.Network != nil {
			return true
		}
	}
	return false
}

func hasMutatingUserAction(plan *users.Plan) bool {
	if plan == nil {
		return false
	}
	for _, act := range plan.Actions {
		if act.Kind != users.AdoptUser {
			return true
		}
	}
	return false
}

func scopeFromFilePath(destPath string, prevState *state.State, resolved *manifest.ResolvedHost) string {
	if strings.HasPrefix(destPath, "/etc/containers/systemd/users/") {
		rest := strings.TrimPrefix(destPath, "/etc/containers/systemd/users/")
		uidStr, _, _ := strings.Cut(rest, "/")
		for _, c := range resolved.Components {
			if !c.Rootful && fmt.Sprintf("%d", c.UID) == uidStr {
				return c.Scope()
			}
		}
		if prevRec, ok := prevState.Files[destPath]; ok && prevRec.Component != "" {
			if reg := resolved.Registry; reg != nil {
				for uName, spec := range reg.Users {
					if fmt.Sprintf("%d", spec.UID) == uidStr {
						return uName
					}
				}
			}
		}
		return ""
	}
	if strings.HasPrefix(destPath, "/etc/containers/systemd/") {
		return RootfulScope
	}
	return ""
}

func inferUserHomeRoot(destPath string) string {
	const prefix = "/var/home/"
	if !strings.HasPrefix(destPath, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(destPath, prefix)
	user, _, ok := strings.Cut(rest, "/")
	if !ok || user == "" {
		return ""
	}
	return prefix + user
}

func unionSortedStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var out []string
	for _, s := range a {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortedBoolKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func cloneStringSliceMap(src map[string][]string) map[string][]string {
	out := make(map[string][]string, len(src))
	for k, v := range src {
		out[k] = slices.Clone(v)
	}
	return out
}

func stringSliceMapsEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || !slices.Equal(va, vb) {
			return false
		}
	}
	return true
}
