package apply

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"quadmatic/internal/manifest"
	"quadmatic/internal/state"
)

type diskFileInfo struct {
	Exists  bool
	Regular bool
	SHA256  string
	Mode    fs.FileMode
	UID     int
	GID     int
}

type fileSnapshotEntry struct {
	Existed  bool
	Content  []byte
	Mode     fs.FileMode
	OwnerUID int
	OwnerGID int
}

type fileSnapshot struct {
	entries map[string]fileSnapshotEntry
}

type rootedTarget struct {
	baseDir    string
	anchorSegs []string
	relSegs    []string
	cleanHost  string
}

func parseRootedTarget(rootDir, hostPath string) (rootedTarget, error) {
	if strings.ContainsRune(hostPath, '\x00') || !strings.HasPrefix(hostPath, "/") {
		return rootedTarget{}, fmt.Errorf("host path %q must be an absolute path", hostPath)
	}
	cleanHost := path.Clean(hostPath)
	if cleanHost == "/" || strings.HasPrefix(cleanHost, "/../") || cleanHost == "/.." {
		return rootedTarget{}, fmt.Errorf("invalid host path %q", hostPath)
	}

	baseDir := "/"
	if rootDir != "" {
		absRoot, err := filepath.Abs(rootDir)
		if err != nil {
			return rootedTarget{}, fmt.Errorf("resolve root dir %q: %w", rootDir, err)
		}
		baseDir = absRoot
	}

	trimmed := strings.TrimPrefix(cleanHost, "/")
	allSegs := strings.Split(trimmed, "/")
	for _, seg := range allSegs {
		if seg == "" || seg == "." || seg == ".." {
			return rootedTarget{}, fmt.Errorf("invalid segment %q in host path %q", seg, hostPath)
		}
	}

	var anchorSegs []string
	relSegs := allSegs
	if strings.HasPrefix(cleanHost, "/var/home/") {
		if len(allSegs) < 4 {
			return rootedTarget{}, fmt.Errorf("rootless path %q must be beneath /var/home/<user>/", hostPath)
		}
		anchorSegs = allSegs[:3]
		relSegs = allSegs[3:]
	}

	return rootedTarget{
		baseDir:    baseDir,
		anchorSegs: anchorSegs,
		relSegs:    relSegs,
		cleanHost:  cleanHost,
	}, nil
}

// openLeafParentRoot traverses from a trusted *os.Root boundary down to the immediate parent
// directory of the target file. Every intermediate directory segment is verified via Lstat and
// opened step-by-step via *os.Root.OpenRoot (O_NOFOLLOW) so symlinks can never be traversed.
func openLeafParentRoot(
	target rootedTarget,
	createMissing bool,
	uid, gid int,
	chownRootHost string,
	chownFn func(string, int, int) error,
) (parentRoot *os.Root, parentAbs string, leafName string, exists bool, err error) {
	curRoot, err := os.OpenRoot(target.baseDir)
	if err != nil {
		if !createMissing && errors.Is(err, os.ErrNotExist) {
			return nil, "", "", false, nil
		}
		return nil, "", "", false, fmt.Errorf("open root %q: %w", target.baseDir, err)
	}

	curAbs := target.baseDir
	curHost := ""
	closeCur := func() {
		if curRoot != nil {
			_ = curRoot.Close()
			curRoot = nil
		}
	}

	allDirSegs := make([]string, 0, len(target.anchorSegs)+len(target.relSegs)-1)
	allDirSegs = append(allDirSegs, target.anchorSegs...)
	allDirSegs = append(allDirSegs, target.relSegs[:len(target.relSegs)-1]...)
	leafName = target.relSegs[len(target.relSegs)-1]

	// Step segment-by-segment from the trusted boundary (e.g. / -> var -> home -> <user> -> .config -> ...),
	// verifying each directory via Lstat and opening via *os.Root.OpenRoot (O_NOFOLLOW).
	for _, seg := range allDirSegs {
		curHost += "/" + seg
		shouldChown := (uid != 0 || gid != 0) && chownRootHost != "" && isSameOrChildHostPath(chownRootHost, curHost)
		perm := fs.FileMode(0o755)
		if shouldChown {
			perm = 0o750
		}
		nextRoot, ok, stepErr := stepRootDir(curRoot, curAbs, seg, createMissing, perm, shouldChown, uid, gid, chownFn)
		closeCur()
		if stepErr != nil {
			return nil, "", "", false, stepErr
		}
		if !ok {
			return nil, "", "", false, nil
		}
		curRoot = nextRoot
		curAbs = filepath.Join(curAbs, seg)
	}

	return curRoot, curAbs, leafName, true, nil
}

func stepRootDir(
	curRoot *os.Root,
	curAbs string,
	seg string,
	createMissing bool,
	perm fs.FileMode,
	shouldChown bool,
	uid, gid int,
	chownFn func(string, int, int) error,
) (nextRoot *os.Root, exists bool, err error) {
	dispPath := filepath.Join(curAbs, seg)
	linfo, err := curRoot.Lstat(seg)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, false, fmt.Errorf("lstat %q: %w", dispPath, err)
		}
		if !createMissing {
			return nil, false, nil
		}
		mkdirErr := curRoot.Mkdir(seg, perm)
		if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
			return nil, false, fmt.Errorf("mkdir %q: %w", dispPath, mkdirErr)
		}
		linfo, err = curRoot.Lstat(seg)
		if err != nil {
			return nil, false, fmt.Errorf("lstat %q: %w", dispPath, err)
		}
		if linfo.Mode()&os.ModeSymlink != 0 {
			return nil, false, fmt.Errorf("refusing to follow symlink directory %q", dispPath)
		}
		if !linfo.IsDir() {
			return nil, false, fmt.Errorf("expected directory at %q, got %s", dispPath, linfo.Mode().Type())
		}
		nextRoot, err = curRoot.OpenRoot(seg)
		if err != nil {
			return nil, false, fmt.Errorf("open directory %q: %w", dispPath, err)
		}
		if mkdirErr == nil && shouldChown {
			if chownFn == nil {
				dirFD, openErr := nextRoot.Open(".")
				if openErr != nil {
					_ = nextRoot.Close()
					return nil, false, fmt.Errorf("open directory %q for chown: %w", dispPath, openErr)
				}
				chownErr := dirFD.Chown(uid, gid)
				_ = dirFD.Close()
				if chownErr != nil {
					_ = nextRoot.Close()
					return nil, false, fmt.Errorf("chown directory %q to %d:%d: %w", dispPath, uid, gid, chownErr)
				}
			} else {
				if chownErr := chownFn(dispPath, uid, gid); chownErr != nil {
					_ = nextRoot.Close()
					return nil, false, fmt.Errorf("chown directory %q to %d:%d: %w", dispPath, uid, gid, chownErr)
				}
			}
		}
		return nextRoot, true, nil
	}

	if linfo.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("refusing to follow symlink directory %q", dispPath)
	}
	if !linfo.IsDir() {
		return nil, false, fmt.Errorf("expected directory at %q, got %s", dispPath, linfo.Mode().Type())
	}

	nextRoot, err = curRoot.OpenRoot(seg)
	if err != nil {
		return nil, false, fmt.Errorf("open directory %q: %w", dispPath, err)
	}
	return nextRoot, true, nil
}

func isSameOrChildHostPath(baseHostPath, candidateHostPath string) bool {
	base := path.Clean(baseHostPath)
	cand := path.Clean(candidateHostPath)
	return cand == base || strings.HasPrefix(cand, base+"/")
}

func inspectDiskFile(rootDir, hostPath string) (diskFileInfo, error) {
	target, err := parseRootedTarget(rootDir, hostPath)
	if err != nil {
		return diskFileInfo{}, err
	}
	dirRoot, dirAbs, leafName, exists, err := openLeafParentRoot(target, false, 0, 0, "", nil)
	if err != nil {
		return diskFileInfo{}, err
	}
	if !exists {
		return diskFileInfo{Exists: false}, nil
	}
	defer dirRoot.Close()

	dispPath := filepath.Join(dirAbs, leafName)
	linfo, err := dirRoot.Lstat(leafName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return diskFileInfo{Exists: false}, nil
		}
		return diskFileInfo{}, fmt.Errorf("lstat %q: %w", dispPath, err)
	}

	out := diskFileInfo{
		Exists:  true,
		Regular: linfo.Mode().IsRegular(),
		Mode:    linfo.Mode().Perm(),
	}
	if st, ok := linfo.Sys().(*syscall.Stat_t); ok {
		out.UID = int(st.Uid)
		out.GID = int(st.Gid)
	}
	if !out.Regular {
		return out, nil
	}

	f, err := dirRoot.Open(leafName)
	if err != nil {
		return diskFileInfo{}, fmt.Errorf("open %q: %w", dispPath, err)
	}
	defer f.Close()

	finfo, err := f.Stat()
	if err != nil {
		return diskFileInfo{}, fmt.Errorf("stat %q: %w", dispPath, err)
	}
	if !finfo.Mode().IsRegular() {
		return diskFileInfo{
			Exists:  true,
			Regular: false,
			Mode:    finfo.Mode().Perm(),
			UID:     out.UID,
			GID:     out.GID,
		}, nil
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return diskFileInfo{}, fmt.Errorf("read %q: %w", dispPath, err)
	}
	out.SHA256 = sha256Hex(data)
	return out, nil
}

func writeFileAtomic(
	rootDir string,
	hostPath string,
	content []byte,
	mode fs.FileMode,
	uid, gid int,
	chownRootHost string,
	chownFn func(string, int, int) error,
) error {
	target, err := parseRootedTarget(rootDir, hostPath)
	if err != nil {
		return err
	}
	dirRoot, dirAbs, leafName, _, err := openLeafParentRoot(target, true, uid, gid, chownRootHost, chownFn)
	if err != nil {
		return err
	}
	defer dirRoot.Close()

	tmpName, tmp, err := createTempInRoot(dirRoot, mode)
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dirAbs, err)
	}
	tmpDispPath := filepath.Join(dirAbs, tmpName)
	cleanup := true
	defer func() {
		if cleanup {
			_ = dirRoot.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file %q: %w", tmpDispPath, err)
	}
	if len(content) > 0 {
		if _, err := tmp.Write(content); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("write temp file %q: %w", tmpDispPath, err)
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file %q: %w", tmpDispPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file %q: %w", tmpDispPath, err)
	}

	if chownFn == nil {
		if err := dirRoot.Chown(tmpName, uid, gid); err != nil {
			return fmt.Errorf("chown temp file %q to %d:%d: %w", tmpDispPath, uid, gid, err)
		}
	} else {
		if err := chownFn(tmpDispPath, uid, gid); err != nil {
			return fmt.Errorf("chown temp file %q to %d:%d: %w", tmpDispPath, uid, gid, err)
		}
	}

	if err := dirRoot.Rename(tmpName, leafName); err != nil {
		return fmt.Errorf("rename temp file %q to %q: %w", tmpDispPath, filepath.Join(dirAbs, leafName), err)
	}
	cleanup = false

	if d, err := dirRoot.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func createTempInRoot(dirRoot *os.Root, mode fs.FileMode) (string, *os.File, error) {
	var buf [8]byte
	for i := 0; i < 100; i++ {
		if _, err := rand.Read(buf[:]); err != nil {
			return "", nil, err
		}
		name := ".quadmatic-" + hex.EncodeToString(buf[:]) + ".tmp"
		f, err := dirRoot.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", nil, err
		}
		return name, f, nil
	}
	return "", nil, errors.New("exhausted temporary filename attempts")
}

func removeFileIfExists(rootDir, hostPath string) error {
	target, err := parseRootedTarget(rootDir, hostPath)
	if err != nil {
		return err
	}
	dirRoot, dirAbs, leafName, exists, err := openLeafParentRoot(target, false, 0, 0, "", nil)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	defer dirRoot.Close()

	err = dirRoot.Remove(leafName)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %q: %w", filepath.Join(dirAbs, leafName), err)
	}
	return nil
}

func captureFileSnapshot(
	rootDir string,
	prevFiles map[string]state.FileRecord,
	desiredFiles map[string]manifest.RenderedFile,
) (*fileSnapshot, error) {
	paths := make(map[string]struct{}, len(prevFiles)+len(desiredFiles))
	for p := range prevFiles {
		paths[p] = struct{}{}
	}
	for p := range desiredFiles {
		paths[p] = struct{}{}
	}

	snap := &fileSnapshot{
		entries: make(map[string]fileSnapshotEntry, len(paths)),
	}
	for destPath := range paths {
		target, err := parseRootedTarget(rootDir, destPath)
		if err != nil {
			return nil, err
		}
		dirRoot, dirAbs, leafName, exists, err := openLeafParentRoot(target, false, 0, 0, "", nil)
		if err != nil {
			return nil, fmt.Errorf("snapshot parent %q: %w", destPath, err)
		}
		if !exists {
			snap.entries[destPath] = fileSnapshotEntry{Existed: false}
			continue
		}

		dispPath := filepath.Join(dirAbs, leafName)
		linfo, err := dirRoot.Lstat(leafName)
		if err != nil {
			_ = dirRoot.Close()
			if errors.Is(err, os.ErrNotExist) {
				snap.entries[destPath] = fileSnapshotEntry{Existed: false}
				continue
			}
			return nil, fmt.Errorf("snapshot lstat %q: %w", dispPath, err)
		}
		if !linfo.Mode().IsRegular() {
			_ = dirRoot.Close()
			// A non-regular file (e.g. out-of-band symlink drift) will be replaced during apply;
			// treat it as not snapshottable rather than aborting drift healing.
			snap.entries[destPath] = fileSnapshotEntry{Existed: false}
			continue
		}

		f, err := dirRoot.Open(leafName)
		if err != nil {
			_ = dirRoot.Close()
			return nil, fmt.Errorf("snapshot open %q: %w", dispPath, err)
		}
		finfo, err := f.Stat()
		if err != nil {
			_ = f.Close()
			_ = dirRoot.Close()
			return nil, fmt.Errorf("snapshot stat %q: %w", dispPath, err)
		}
		if !finfo.Mode().IsRegular() {
			_ = f.Close()
			_ = dirRoot.Close()
			snap.entries[destPath] = fileSnapshotEntry{Existed: false}
			continue
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		_ = dirRoot.Close()
		if err != nil {
			return nil, fmt.Errorf("snapshot read %q: %w", dispPath, err)
		}

		uid, gid := 0, 0
		if st, ok := linfo.Sys().(*syscall.Stat_t); ok {
			uid = int(st.Uid)
			gid = int(st.Gid)
		}
		if rec, ok := prevFiles[destPath]; ok && rootDir != "" {
			uid = rec.OwnerUID
			gid = rec.OwnerGID
		}
		snap.entries[destPath] = fileSnapshotEntry{
			Existed:  true,
			Content:  data,
			Mode:     linfo.Mode().Perm(),
			OwnerUID: uid,
			OwnerGID: gid,
		}
	}
	return snap, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}
