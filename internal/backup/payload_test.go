package backup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/keyfile"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

// seed creates a data dir with a live store and every required CONFIG_DIR file.
func seed(t *testing.T) (*store.Store, string, string) {
	t.Helper()
	dataDir := t.TempDir()
	configDir := filepath.Join(dataDir, "configdir")
	st, err := store.NewStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for _, name := range []string{"audit.key", "enum.key", "deployment.key"} {
		if _, err := keyfile.LoadOrCreate(filepath.Join(configDir, name), 32); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configDir, "audit.state"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "audit"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "audit", "audit.log"), []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	return st, dataDir, configDir
}

// A commit still in the WAL must be in the snapshot; copying the file would miss it.
func TestCollectSeesUncheckpointedCommit(t *testing.T) {
	st, dataDir, configDir := seed(t)
	if err := st.SetSetting("canary", "in-the-wal"); err != nil {
		t.Fatal(err)
	}

	p, err := Collect(context.Background(), st, dataDir, configDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if p.ServiceName != AppName {
		t.Fatalf("service %q", p.ServiceName)
	}
	var db []byte
	for _, f := range p.Files {
		if f.Path == dbMember {
			db = f.Data
		}
	}
	if db == nil {
		t.Fatal("no database member")
	}
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := os.WriteFile(snap, db, 0600); err != nil {
		t.Fatal(err)
	}
	conn, err := sql.Open("sqlite", snap)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var v string
	if err := conn.QueryRow(`SELECT value FROM settings WHERE key = 'canary'`).Scan(&v); err != nil || v != "in-the-wal" {
		t.Fatalf("snapshot lost the WAL row: %v %q", err, v)
	}
	if entries, _ := os.ReadDir(dataDir); len(entries) > 0 {
		for _, e := range entries {
			if e.IsDir() && len(e.Name()) > 8 && e.Name()[:8] == "snapshot" {
				t.Fatal("snapshot scratch directory left behind")
			}
		}
	}
}

func TestCollectRefusesWithoutAuditKey(t *testing.T) {
	dataDir := t.TempDir()
	st, err := store.NewStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Collect(context.Background(), st, dataDir, filepath.Join(dataDir, "configdir"), "test"); err == nil {
		t.Fatal("a capsule without the audit key restores a server that refuses to start; Collect must refuse")
	}
}
