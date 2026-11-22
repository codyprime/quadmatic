package users

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type subIDLine struct {
	raw   string
	entry *SubIDEntry
}

// ParsePasswd parses /etc/passwd formatted bytes into PasswdEntry records.
func ParsePasswd(data []byte) ([]PasswdEntry, error) {
	lines := strings.Split(string(data), "\n")
	entries := make([]PasswdEntry, 0, len(lines))
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return nil, fmt.Errorf("passwd line %d: expected 7 colon-separated fields, got %d", i+1, len(fields))
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("passwd line %d: invalid uid %q: %w", i+1, fields[2], err)
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			return nil, fmt.Errorf("passwd line %d: invalid gid %q: %w", i+1, fields[3], err)
		}
		entries = append(entries, PasswdEntry{
			Name:  fields[0],
			UID:   uid,
			GID:   gid,
			GECOS: fields[4],
			Home:  fields[5],
			Shell: fields[6],
		})
	}
	return entries, nil
}

func readPasswd(path string) ([]PasswdEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read passwd %q: %w", path, err)
	}
	return ParsePasswd(data)
}

// ParseSubID parses /etc/subuid or /etc/subgid formatted bytes into SubIDEntry records.
func ParseSubID(data []byte) ([]SubIDEntry, error) {
	lines, err := parseSubIDLines(data)
	if err != nil {
		return nil, err
	}
	entries := make([]SubIDEntry, 0, len(lines))
	for _, l := range lines {
		if l.entry != nil {
			entries = append(entries, *l.entry)
		}
	}
	return entries, nil
}

func parseSubIDLines(data []byte) ([]subIDLine, error) {
	rawLines := strings.Split(string(data), "\n")
	if len(rawLines) > 0 && rawLines[len(rawLines)-1] == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}
	parsed := make([]subIDLine, 0, len(rawLines))
	for i, line := range rawLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			parsed = append(parsed, subIDLine{raw: line})
			continue
		}
		fields := strings.Split(trimmed, ":")
		if len(fields) != 3 || fields[0] == "" {
			return nil, fmt.Errorf("subid line %d: expected name:start:count, got %q", i+1, line)
		}
		start, err := strconv.Atoi(fields[1])
		if err != nil || start < 0 {
			return nil, fmt.Errorf("subid line %d: invalid start %q", i+1, fields[1])
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil || count <= 0 {
			return nil, fmt.Errorf("subid line %d: invalid count %q", i+1, fields[2])
		}
		entry := SubIDEntry{
			Name:  fields[0],
			Start: start,
			Count: count,
		}
		parsed = append(parsed, subIDLine{raw: line, entry: &entry})
	}
	return parsed, nil
}

func readSubIDFile(path string) ([]SubIDEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read subid file %q: %w", path, err)
	}
	return ParseSubID(data)
}

// CheckSubIDOverlap returns an error if target overlaps any entry in existing
// belonging to a different user, or if any range is invalid/overflows.
func CheckSubIDOverlap(existing []SubIDEntry, target SubIDEntry) error {
	if target.Start < 0 || target.Count <= 0 || target.Start > math.MaxInt-target.Count {
		return fmt.Errorf("invalid subid range for %q (%d:%d)", target.Name, target.Start, target.Count)
	}
	targetEnd := target.Start + target.Count
	for _, e := range existing {
		if e.Name == target.Name {
			continue
		}
		if e.Start < 0 || e.Count <= 0 || e.Start > math.MaxInt-e.Count {
			return fmt.Errorf("invalid existing subid range for %q (%d:%d)", e.Name, e.Start, e.Count)
		}
		existingEnd := e.Start + e.Count
		if e.Start < targetEnd && target.Start < existingEnd {
			return fmt.Errorf(
				"subid range for %q (%d:%d) overlaps existing entry for %q (%d:%d)",
				target.Name, target.Start, target.Count, e.Name, e.Start, e.Count,
			)
		}
	}
	return nil
}

func subIDMatches(entries []SubIDEntry, name string, start, count int) bool {
	matched := 0
	for _, e := range entries {
		if e.Name != name {
			continue
		}
		if e.Start != start || e.Count != count {
			return false
		}
		matched++
	}
	return matched == 1
}

func applySubIDUpdatesAtomic(path string, updates []SubIDEntry) error {
	var existingData []byte
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read subid file %q: %w", path, err)
	}
	existingData = data

	lines, err := parseSubIDLines(existingData)
	if err != nil {
		return fmt.Errorf("parse subid file %q: %w", path, err)
	}

	existingEntries := make([]SubIDEntry, 0, len(lines))
	for _, l := range lines {
		if l.entry != nil {
			existingEntries = append(existingEntries, *l.entry)
		}
	}
	for _, upd := range updates {
		if err := CheckSubIDOverlap(existingEntries, upd); err != nil {
			return err
		}
	}

	updateMap := make(map[string]SubIDEntry, len(updates))
	for _, upd := range updates {
		updateMap[upd.Name] = upd
	}

	written := make(map[string]bool, len(updates))
	outLines := make([]string, 0, len(lines)+len(updates))
	for _, l := range lines {
		if l.entry == nil {
			outLines = append(outLines, l.raw)
			continue
		}
		upd, isUpdated := updateMap[l.entry.Name]
		if !isUpdated {
			outLines = append(outLines, l.raw)
			continue
		}
		if !written[upd.Name] {
			outLines = append(outLines, formatSubIDEntry(upd))
			written[upd.Name] = true
		}
	}

	for _, upd := range updates {
		if !written[upd.Name] {
			outLines = append(outLines, formatSubIDEntry(upd))
			written[upd.Name] = true
		}
	}

	content := ""
	if len(outLines) > 0 {
		content = strings.Join(outLines, "\n") + "\n"
	}
	return writeFileAtomic(path, []byte(content), 0o644)
}

func formatSubIDEntry(e SubIDEntry) string {
	return fmt.Sprintf("%s:%d:%d", e.Name, e.Start, e.Count)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("ensure parent dir %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".quadmatic-*")
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file %q: %w", tmpName, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file %q: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file %q: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file %q: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %q to %q: %w", tmpName, path, err)
	}
	cleanup = false
	return nil
}
