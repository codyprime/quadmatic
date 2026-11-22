package apply

import (
	"crypto/sha256"
	"errors"
	"fmt"
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

func resolveHostPath(rootDir, hostPath string) (string, error) {
	if strings.ContainsRune(hostPath, '\x00') || !strings.HasPrefix(hostPath, "/") {
		return "", fmt.Errorf("host path %q must be an absolute path", hostPath)
	}
	cleanHost := path.Clean(hostPath)
	if cleanHost == "/" || strings.HasPrefix(cleanHost, "/../") {
		return "", fmt.Errorf("invalid host path %q", hostPath)
	}
	if rootDir == "" {
		return cleanHost, nil
	}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", fmt.Errorf("resolve root dir %q: %w", rootDir, err)
	}
	rel := strings.TrimPrefix(cleanHost, "/")
	joined := filepath.Join(absRoot, filepath.FromSlash(rel))
	relCheck, err := filepath.Rel(absRoot, joined)
	if err != nil {
		return "", err
	}
	if relCheck == "." || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes root dir %q", hostPath, rootDir)
	}
	return joined, nil
}

func inspectDiskFile(absPath string) (diskFileInfo, error) {
	linfo, err := os.Lstat(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return diskFileInfo{Exists: false}, nil
		}
		return diskFileInfo{}, fmt.Errorf("lstat %q: %w", absPath, err)
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

	data, err := os.ReadFile(absPath)
	if err != nil {
		return diskFileInfo{}, fmt.Errorf("read %q: %w", absPath, err)
	}
	out.SHA256 = sha256Hex(data)
	return out, nil
}

func writeFileAtomic(
	absPath string,
	content []byte,
	mode fs.FileMode,
	uid, gid int,
	chownRootAbs string,
	chownFn func(string, int, int) error,
) error {
	dir := filepath.Dir(absPath)
	if err := ensureParentDirs(dir, uid, gid, chownRootAbs, chownFn); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".quadmatic-*.tmp")
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

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file %q: %w", tmpName, err)
	}
	if len(content) > 0 {
		if _, err := tmp.Write(content); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("write temp file %q: %w", tmpName, err)
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file %q: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file %q: %w", tmpName, err)
	}

	if chownFn != nil {
		if err := chownFn(tmpName, uid, gid); err != nil {
			return fmt.Errorf("chown temp file %q to %d:%d: %w", tmpName, uid, gid, err)
		}
	}

	if err := os.Rename(tmpName, absPath); err != nil {
		return fmt.Errorf("rename temp file %q to %q: %w", tmpName, absPath, err)
	}
	cleanup = false

	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func ensureParentDirs(targetDir string, uid, gid int, chownRootAbs string, chownFn func(string, int, int) error) error {
	cleanDir := filepath.Clean(targetDir)
	if _, err := os.Stat(cleanDir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat directory %q: %w", cleanDir, err)
	}

	// Collect missing directories from deepest up to an existing ancestor, then create top-down
	// so newly created directories under chownRootAbs receive user ownership and 0750 permissions.
	var toCreate []string
	cur := cleanDir
	for {
		_, err := os.Stat(cur)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat directory %q: %w", cur, err)
		}
		toCreate = append(toCreate, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}

	for i := len(toCreate) - 1; i >= 0; i-- {
		d := toCreate[i]
		shouldChown := (uid != 0 || gid != 0) && chownRootAbs != "" && isSameOrChildDir(chownRootAbs, d)
		perm := fs.FileMode(0o755)
		if shouldChown {
			perm = 0o750
		}
		if err := os.Mkdir(d, perm); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("mkdir %q: %w", d, err)
		}
		if shouldChown && chownFn != nil {
			if err := chownFn(d, uid, gid); err != nil {
				return fmt.Errorf("chown directory %q to %d:%d: %w", d, uid, gid, err)
			}
		}
	}
	return nil
}

func isSameOrChildDir(baseDir, candidate string) bool {
	rel, err := filepath.Rel(filepath.Clean(baseDir), filepath.Clean(candidate))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func removeFileIfExists(absPath string) error {
	err := os.Remove(absPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %q: %w", absPath, err)
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
		absPath, err := resolveHostPath(rootDir, destPath)
		if err != nil {
			return nil, err
		}
		linfo, err := os.Lstat(absPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				snap.entries[destPath] = fileSnapshotEntry{Existed: false}
				continue
			}
			return nil, fmt.Errorf("snapshot lstat %q: %w", absPath, err)
		}
		if !linfo.Mode().IsRegular() {
			// A non-regular file (e.g. out-of-band symlink drift) will be replaced during apply;
			// treat it as not snapshottable rather than aborting drift healing.
			snap.entries[destPath] = fileSnapshotEntry{Existed: false}
			continue
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			return nil, fmt.Errorf("snapshot read %q: %w", absPath, err)
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
