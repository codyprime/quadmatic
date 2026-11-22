package users

import (
	"fmt"
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
			spec.SubUIDStart = *ru.SubUIDStart
		}
		if ru.SubUIDCount != nil {
			if *ru.SubUIDCount <= 0 {
				return nil, fmt.Errorf("user %q subuid_count %d must be positive", name, *ru.SubUIDCount)
			}
			spec.SubUIDCount = *ru.SubUIDCount
		}

		start, count := SubIDRange(uid, spec, subidCfg)
		if start <= 0 || count <= 0 {
			return nil, fmt.Errorf("computed subid range (%d:%d) for user %q is invalid (set subuid_start override or adjust uid_base)", start, count, name)
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
		cfg.Base = *raw.Base
	}
	if raw.UIDBase != nil {
		if *raw.UIDBase <= 0 {
			return SubIDConfig{}, fmt.Errorf("subid.uid_base %d must be positive", *raw.UIDBase)
		}
		cfg.UIDBase = *raw.UIDBase
	}
	if raw.Count != nil {
		if *raw.Count <= 0 {
			return SubIDConfig{}, fmt.Errorf("subid.count %d must be positive", *raw.Count)
		}
		cfg.Count = *raw.Count
	}
	return cfg, nil
}

// SubIDRange computes the deterministic (start, count) subuid/subgid range for uid,
// honoring explicit per-user overrides when set.
func SubIDRange(uid int, spec UserSpec, cfg SubIDConfig) (start, count int) {
	count = cfg.Count
	if count <= 0 {
		count = defaultSubIDCount
	}
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
	return base + (uid-uidBase)*count, count
}
