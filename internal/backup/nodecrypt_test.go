package backup_test

import (
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient/guardtest"
)

// Nothing in this server opens a capsule sealed to the suite key, combines shares or
// rebuilds the key from a seed, except the restore subcommand. The walk starts from an
// absolute repo root and fails on fewer than guardtest.MinFiles, so it cannot pass vacuously.
func TestNothingInTheServerDecrypts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	guardtest.NoDecryptOutside(t, root, map[string][]string{
		filepath.Join("cmd", "server", "backup.go"): {"restore"},
	})
}
