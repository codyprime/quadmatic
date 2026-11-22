package users

import (
	"fmt"
	"math"
	"math/bits"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	defaultSubIDBase    = 1_000_000
	defaultSubIDUIDBase = 2000
	defaultSubIDCount   = 65536
	minServiceUID       = 1000
	reservedRootfulUser = "rootful"
)

var validUsernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

type rawSubIDConfig struct {
	Base    *int `toml:"base"`
	UIDBase *int `toml:"uid_base"`
	Count   *int `toml:"count"`
}

type rawUserSpec struct {
	UID         *int `toml:"uid"`
	SubUIDStart *int `toml:"subuid_start"`
	SubUIDCount *int `toml:"subuid_count"`
}

type rawRegistry struct {
	SubID rawSubIDConfig         `toml:"subid"`
	Users map[string]rawUserSpec `toml:"users"`
}

// LoadRegistry reads and parses a users.toml registry file from path.
func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read users registry %q: %w", path, err)
	}
	return ParseRegistry(data)
}

// ParseRegistry decodes raw TOML bytes into a validated Registry with defaults applied.
func ParseRegistry(data []byte) (*Registry, error) {
	var raw rawRegistry
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, fmt.Errorf("decode users registry: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("unknown users registry key(s): %s", strings.Join(keys, ", "))
	}

	subidCfg, err := resolveSubIDConfig(raw.SubID)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(raw.Users))
	for name := range raw.Users {
		names = append(names, name)
	}
	sort.Strings(names)

	usersMap := make(map[string]UserSpec, len(names))
	seenUIDs := make(map[int]string, len(names))
	assignedRanges := make([]SubIDEntry, 0, len(names))

	for _, name := range names {
		if name == reservedRootfulUser {
			return nil, fmt.Errorf("invalid username %q: reserved scope name", name)
		}
		if !validUsernameRe.MatchString(name) {
			return nil, fmt.Errorf("invalid username %q: must match %s", name, validUsernameRe.String())
		}
		ru := raw.Users[name]
		if ru.UID == nil {
			return nil, fmt.Errorf("user %q missing required field \"uid\"", name)
		}
		uid := *ru.UID
		if uid < minServiceUID {
			return nil, fmt.Errorf("user %q UID %d must be >= %d", name, uid, minServiceUID)
		}
		if uint64(uid) > math.MaxUint32 {
			return nil, fmt.Errorf("user %q UID %d exceeds uint32 maximum (%d)", name, uid, uint32(math.MaxUint32))
		}
		if prevUser, dup := seenUIDs[uid]; dup {
			return nil, fmt.Errorf("duplicate UID %d shared by %q and %q", uid, prevUser, name)
		}
		seenUIDs[uid] = name

		spec := UserSpec{
			Name: name,
			UID:  uid,
		}
		if ru.SubUIDStart != nil {
			if *ru.SubUIDStart <= 0 {
				return nil, fmt.Errorf("user %q subuid_start %d must be positive", name, *ru.SubUIDStart)
			}
			if uint64(*ru.SubUIDStart) > math.MaxUint32 {
				return nil, fmt.Errorf("user %q subuid_start %d exceeds uint32 maximum (%d)", name, *ru.SubUIDStart, uint32(math.MaxUint32))
			}
			spec.SubUIDStart = *ru.SubUIDStart
		}
		if ru.SubUIDCount != nil {
			if *ru.SubUIDCount <= 0 {
				return nil, fmt.Errorf("user %q subuid_count %d must be positive", name, *ru.SubUIDCount)
			}
			if uint64(*ru.SubUIDCount) > math.MaxUint32 {
				return nil, fmt.Errorf("user %q subuid_count %d exceeds uint32 maximum (%d)", name, *ru.SubUIDCount, uint32(math.MaxUint32))
			}
			spec.SubUIDCount = *ru.SubUIDCount
		}

		start, count, err := computeSubIDRange(uid, spec, subidCfg)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", name, err)
		}

		entry := SubIDEntry{Name: name, Start: start, Count: count}
		if err := CheckSubIDOverlap(assignedRanges, entry); err != nil {
			return nil, fmt.Errorf("registry subid conflict: %w", err)
		}
		assignedRanges = append(assignedRanges, entry)
		usersMap[name] = spec
	}

	return &Registry{
		SubID: subidCfg,
		Users: usersMap,
	}, nil
}

func resolveSubIDConfig(raw rawSubIDConfig) (SubIDConfig, error) {
	cfg := SubIDConfig{
		Base:    defaultSubIDBase,
		UIDBase: defaultSubIDUIDBase,
		Count:   defaultSubIDCount,
	}
	if raw.Base != nil {
		if *raw.Base <= 0 {
			return SubIDConfig{}, fmt.Errorf("subid.base %d must be positive", *raw.Base)
		}
		if uint64(*raw.Base) > math.MaxUint32 {
			return SubIDConfig{}, fmt.Errorf("subid.base %d exceeds uint32 maximum (%d)", *raw.Base, uint32(math.MaxUint32))
		}
		cfg.Base = *raw.Base
	}
	if raw.UIDBase != nil {
		if *raw.UIDBase <= 0 {
			return SubIDConfig{}, fmt.Errorf("subid.uid_base %d must be positive", *raw.UIDBase)
		}
		if uint64(*raw.UIDBase) > math.MaxUint32 {
			return SubIDConfig{}, fmt.Errorf("subid.uid_base %d exceeds uint32 maximum (%d)", *raw.UIDBase, uint32(math.MaxUint32))
		}
		cfg.UIDBase = *raw.UIDBase
	}
	if raw.Count != nil {
		if *raw.Count <= 0 {
			return SubIDConfig{}, fmt.Errorf("subid.count %d must be positive", *raw.Count)
		}
		if uint64(*raw.Count) > math.MaxUint32 {
			return SubIDConfig{}, fmt.Errorf("subid.count %d exceeds uint32 maximum (%d)", *raw.Count, uint32(math.MaxUint32))
		}
		cfg.Count = *raw.Count
	}
	return cfg, nil
}

func computeSubIDRange(uid int, spec UserSpec, cfg SubIDConfig) (start, count int, err error) {
	stride := cfg.Count
	if stride <= 0 {
		stride = defaultSubIDCount
	}
	count = stride
	if spec.SubUIDCount > 0 {
		count = spec.SubUIDCount
	}
	if count <= 0 || uint64(count) > math.MaxUint32 {
		return 0, 0, fmt.Errorf("computed subid count %d is out of uint32 range", count)
	}

	if spec.SubUIDStart > 0 {
		start = spec.SubUIDStart
		if uint64(start) > math.MaxUint32 {
			return 0, 0, fmt.Errorf("subuid_start %d exceeds uint32 maximum (%d)", start, uint32(math.MaxUint32))
		}
	} else {
		base := cfg.Base
		if base <= 0 {
			base = defaultSubIDBase
		}
		if uint64(base) > math.MaxUint32 {
			return 0, 0, fmt.Errorf("subid.base %d exceeds uint32 maximum (%d)", base, uint32(math.MaxUint32))
		}
		uidBase := cfg.UIDBase
		if uidBase <= 0 {
			uidBase = defaultSubIDUIDBase
		}
		if uint64(stride) > math.MaxUint32 {
			return 0, 0, fmt.Errorf("subid.count %d exceeds uint32 maximum (%d)", stride, uint32(math.MaxUint32))
		}

		if uid >= uidBase {
			delta := uint64(uid - uidBase)
			hi, prod := bits.Mul64(delta, uint64(stride))
			if hi != 0 || prod > math.MaxUint32 {
				return 0, 0, fmt.Errorf("computed subid start overflows uint32 maximum (%d)", uint32(math.MaxUint32))
			}
			start64 := uint64(base) + prod
			if start64 == 0 || start64 > math.MaxUint32 {
				return 0, 0, fmt.Errorf("computed subid start %d exceeds uint32 maximum (%d)", start64, uint32(math.MaxUint32))
			}
			start = int(start64)
		} else {
			negDelta := uint64(uidBase - uid)
			hi, prod := bits.Mul64(negDelta, uint64(stride))
			if hi != 0 || prod >= uint64(base) {
				return 0, 0, fmt.Errorf("computed subid range is non-positive (set subuid_start override or adjust uid_base)")
			}
			start64 := uint64(base) - prod
			if start64 > math.MaxUint32 {
				return 0, 0, fmt.Errorf("computed subid start %d exceeds uint32 maximum (%d)", start64, uint32(math.MaxUint32))
			}
			start = int(start64)
		}
	}

	if start <= 0 || uint64(start) > math.MaxUint32 {
		return 0, 0, fmt.Errorf("computed subid range (%d:%d) is invalid (set subuid_start override or adjust uid_base)", start, count)
	}
	if uint64(start)+uint64(count)-1 > math.MaxUint32 {
		return 0, 0, fmt.Errorf("computed subid range (%d:%d) exceeds uint32 maximum (%d)", start, count, uint32(math.MaxUint32))
	}
	return start, count, nil
}

// SubIDRange computes the deterministic (start, count) subuid/subgid range for uid,
// honoring explicit per-user overrides when set. When subuid_start is omitted (0),
// UID stride is computed strictly from cfg.Count (defaulting to 65536), not spec.SubUIDCount.
func SubIDRange(uid int, spec UserSpec, cfg SubIDConfig) (start, count int) {
	stride := cfg.Count
	if stride <= 0 {
		stride = defaultSubIDCount
	}
	count = stride
	if spec.SubUIDCount > 0 {
		count = spec.SubUIDCount
	}
	if spec.SubUIDStart > 0 {
		return spec.SubUIDStart, count
	}
	base := cfg.Base
	if base <= 0 {
		base = defaultSubIDBase
	}
	uidBase := cfg.UIDBase
	if uidBase <= 0 {
		uidBase = defaultSubIDUIDBase
	}
	return base + (uid-uidBase)*stride, count
}
