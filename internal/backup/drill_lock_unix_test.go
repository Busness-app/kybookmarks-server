//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package backup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient"
)

func TestDrillLockSubprocess(t *testing.T) {
	if root := os.Getenv("KYBOOKMARKS_TEST_DRILL_ROOT"); root != "" {
		lock, err := lockDrill(root)
		if os.Getenv("KYBOOKMARKS_TEST_DRILL_BUSY") == "1" {
			if !errors.Is(err, recoveryclient.ErrInProgress) {
				if lock != nil {
					lock.Close()
				}
				t.Fatalf("expected busy: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			lock.Close()
		}
		return
	}
	st, dataDir, configDir := seed(t)
	root, err := DrillRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := lockDrill(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	child := func(path, busy string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestDrillLockSubprocess$")
		cmd.Env = append(os.Environ(), "KYBOOKMARKS_TEST_DRILL_ROOT="+path, "KYBOOKMARKS_TEST_DRILL_BUSY="+busy)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v %s", err, out)
		}
	}
	child(root, "1")
	// An alias reaches the same inode, not a separate string-keyed mutex.
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	child(alias, "1")
	other, err := DrillRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	child(other, "0")
	if _, err := RunDrill(context.Background(), st, dataDir, configDir, "test"); !errors.Is(err, recoveryclient.ErrInProgress) {
		t.Fatalf("wrapper bypassed lock: %v", err)
	}
	lock.Close()
	child(root, "0")
	// Collection failure releases the descriptor, so another process can proceed.
	if err := os.Remove(filepath.Join(configDir, "audit.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := RunDrill(context.Background(), st, dataDir, configDir, "test"); err == nil {
		t.Fatal("missing key accepted")
	}
	child(root, "0")
}

func TestDrillRootTightensExistingPermissions(t *testing.T) {
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "drill")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := DrillRoot(dataDir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(root)
	if err != nil || fi.Mode().Perm() != 0700 {
		t.Fatalf("root permissions: %v %v", fi, err)
	}
}
