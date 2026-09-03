package api

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSaltKeyIsStableAcrossLoads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	first, err := loadOrCreateSaltKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateSaltKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("salt key changed between loads")
	}
}

// TestSaltKeyReportsWhenItCannotPersist: a key that cannot be written would
// rotate every restart and leak which usernames exist. That must not be silent.
func TestSaltKeyReportsWhenItCannotPersist(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := loadOrCreateSaltKey(dir); err == nil {
		t.Fatal("unwritable config dir produced a key with no error")
	}
	if _, err := loadOrCreateSaltKey(""); err == nil {
		t.Fatal("empty config dir produced a key with no error")
	}
}
