package apply

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quadmatic/internal/manifest"
	"quadmatic/internal/state"
)

func TestRootedFileOpsRejectSymlinkIntermediateDirs(t *testing.T) {
	setupTarget := func(t *testing.T, symlinkKind string) (rootDir string, destPath string, outsideFile string) {
		t.Helper()
		base := t.TempDir()
		rootDir = filepath.Join(base, "rootfs")
		outsideDir := filepath.Join(base, "outside")
		if err := os.MkdirAll(outsideDir, 0o755); err != nil {
			t.Fatal(err)
		}
		outsideFile = filepath.Join(outsideDir, "config.yaml")
		if err := os.WriteFile(outsideFile, []byte("untouched-secret\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		userHome := filepath.Join(rootDir, "var", "home", "openwebui")
		switch symlinkKind {
		case "dotconfig-outside":
			if err := os.MkdirAll(userHome, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsideDir, filepath.Join(userHome, ".config")); err != nil {
				t.Fatal(err)
			}
		case "component-outside":
			quadmaticDir := filepath.Join(userHome, ".config", "quadmatic")
			if err := os.MkdirAll(quadmaticDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsideDir, filepath.Join(quadmaticDir, "open-webui")); err != nil {
				t.Fatal(err)
			}
		case "dotconfig-relative-inside":
			if err := os.MkdirAll(filepath.Join(userHome, "real-ssh"), 0o755); err != nil {
				t.Fatal(err)
			}
			insideTarget := filepath.Join(userHome, "real-ssh", "config.yaml")
			if err := os.WriteFile(insideTarget, []byte("untouched-secret\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			outsideFile = insideTarget
			if err := os.Symlink("real-ssh", filepath.Join(userHome, ".config")); err != nil {
				t.Fatal(err)
			}
			destPath = "/var/home/openwebui/.config/config.yaml"
			return rootDir, destPath, outsideFile
		case "userhome-outside":
			homeParent := filepath.Join(rootDir, "var", "home")
			if err := os.MkdirAll(homeParent, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsideDir, filepath.Join(homeParent, "openwebui")); err != nil {
				t.Fatal(err)
			}
		case "rootful-etc-outside":
			etcContainers := filepath.Join(rootDir, "etc", "containers")
			if err := os.MkdirAll(etcContainers, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsideDir, filepath.Join(etcContainers, "systemd")); err != nil {
				t.Fatal(err)
			}
			destPath = "/etc/containers/systemd/config.yaml"
			return rootDir, destPath, outsideFile
		default:
			t.Fatalf("unknown symlinkKind %q", symlinkKind)
		}
		destPath = "/var/home/openwebui/.config/quadmatic/open-webui/config.yaml"
		return rootDir, destPath, outsideFile
	}

	cases := []string{
		"dotconfig-outside",
		"component-outside",
		"dotconfig-relative-inside",
		"userhome-outside",
		"rootful-etc-outside",
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			rootDir, destPath, targetFile := setupTarget(t, tc)

			if _, err := inspectDiskFile(rootDir, destPath); err == nil {
				t.Fatalf("inspectDiskFile unexpectedly succeeded across symlink (%s)", tc)
			} else if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
				t.Fatalf("inspectDiskFile error should mention symlink, got: %v", err)
			}

			var chownCalled bool
			err := writeFileAtomic(rootDir, destPath, []byte("hijacked\n"), 0o640, 2001, 2001, "/var/home/openwebui", func(p string, uid, gid int) error {
				chownCalled = true
				return fmt.Errorf("unexpected chown call %s %d:%d", p, uid, gid)
			})
			if err == nil {
				t.Fatalf("writeFileAtomic unexpectedly succeeded across symlink (%s)", tc)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
				t.Fatalf("writeFileAtomic error should mention symlink, got: %v", err)
			}
			if chownCalled {
				t.Fatalf("writeFileAtomic called chown across symlink (%s)", tc)
			}

			_, err = captureFileSnapshot(rootDir, map[string]state.FileRecord{
				destPath: {SHA256: "abc", Mode: 0o640},
			}, map[string]manifest.RenderedFile{
				destPath: {DestPath: destPath, Content: []byte("new")},
			})
			if err == nil {
				t.Fatalf("captureFileSnapshot unexpectedly succeeded across symlink (%s)", tc)
			} else if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
				t.Fatalf("captureFileSnapshot error should mention symlink, got: %v", err)
			}

			if err := removeFileIfExists(rootDir, destPath); err == nil {
				t.Fatalf("removeFileIfExists unexpectedly succeeded across symlink (%s)", tc)
			} else if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
				t.Fatalf("removeFileIfExists error should mention symlink, got: %v", err)
			}

			got, readErr := os.ReadFile(targetFile)
			if readErr != nil {
				t.Fatalf("symlink target %q was damaged/removed: %v", targetFile, readErr)
			}
			if string(got) != "untouched-secret\n" {
				t.Fatalf("symlink target %q was modified: %q", targetFile, string(got))
			}
		})
	}
}

func TestRootedFileOpsHappyPathAndRootChown(t *testing.T) {
	rootDir := t.TempDir()
	destPath := "/var/home/openwebui/.config/quadmatic/open-webui/config.yaml"
	uid := os.Getuid()
	gid := os.Getgid()

	if err := writeFileAtomic(rootDir, destPath, []byte("hello: world\n"), 0o640, uid, gid, "/var/home/openwebui", nil); err != nil {
		t.Fatalf("writeFileAtomic failed: %v", err)
	}

	info, err := inspectDiskFile(rootDir, destPath)
	if err != nil {
		t.Fatalf("inspectDiskFile failed: %v", err)
	}
	if !info.Exists || !info.Regular || info.Mode != 0o640 || info.SHA256 != sha256Hex([]byte("hello: world\n")) {
		t.Fatalf("unexpected diskFileInfo: %+v", info)
	}

	snap, err := captureFileSnapshot(rootDir, nil, map[string]manifest.RenderedFile{
		destPath: {DestPath: destPath},
	})
	if err != nil {
		t.Fatalf("captureFileSnapshot failed: %v", err)
	}
	entry := snap.entries[destPath]
	if !entry.Existed || string(entry.Content) != "hello: world\n" || entry.Mode != 0o640 {
		t.Fatalf("unexpected snapshot entry: %+v", entry)
	}

	if err := removeFileIfExists(rootDir, destPath); err != nil {
		t.Fatalf("removeFileIfExists failed: %v", err)
	}
	infoAfter, err := inspectDiskFile(rootDir, destPath)
	if err != nil {
		t.Fatalf("inspectDiskFile after remove failed: %v", err)
	}
	if infoAfter.Exists {
		t.Fatalf("expected file to be removed, got %+v", infoAfter)
	}
}
