package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

func TestChecksFailOnMissingDatabase(t *testing.T) {
	dir := t.TempDir()
	checks := Checks(dir, capsule.Manifest{UnverifiedManifest: capsule.UnverifiedManifest{Files: []capsule.FileEntry{{Path: dbMember}}}})
	for _, c := range checks {
		if c.Name == "Database present: "+dbMember && !c.Passed {
			return
		}
	}
	t.Fatal("missing database was not reported")
}

// The real drill: seal what Collect produces to a throwaway key, open it, run Checks.
func TestDrillPassesOnASeededInstance(t *testing.T) {
	st, dataDir, configDir := seed(t)
	if err := st.SetSetting("x", "y"); err != nil {
		t.Fatal(err)
	}
	// The drill wants an active admin; seed one.
	admin := &store.Account{Username: "owner", Email: "owner@example.com", PasswordHash: "x", AuthSalt: "00", KDFIterations: 1, Role: "admin", Status: "active"}
	if err := st.CreateAccount(admin); err != nil {
		t.Fatal(err)
	}
	p, err := Collect(context.Background(), st, dataDir, configDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	root, err := DrillRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := recoveryclient.Drill(context.Background(), root, p, Checks)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Checks {
		if !c.Passed {
			t.Errorf("%s: %s", c.Name, c.Message)
		}
	}
	if !res.Passed {
		t.Fatal("drill failed")
	}
}

func TestDrillRootIsUnderTheDataDirAndExists(t *testing.T) {
	dataDir := t.TempDir()
	root, err := DrillRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if root != dataDir+"/drill" {
		t.Fatal(root)
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0700 {
		t.Fatalf("drill root: %v %v", fi, err)
	}
}

// checksFixture emulates the opened boundary (JSON maps/lists) without invoking the
// application's schema-creating store API on the extracted database.
func checksFixture(t *testing.T) (string, capsule.Manifest) {
	t.Helper()
	st, dataDir, configDir := seed(t)
	if err := st.CreateAccount(&store.Account{Username: "owner", Email: "owner@example.com", PasswordHash: "x", AuthSalt: "00", KDFIterations: 1, Role: "admin", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	p, err := Collect(context.Background(), st, dataDir, configDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "scratch ?#%")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	m := capsule.Manifest{UnverifiedManifest: capsule.UnverifiedManifest{ServiceName: AppName}}
	raw, err := json.Marshal(p.VerificationRecipe)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m.VerificationRecipe); err != nil {
		t.Fatal(err)
	}
	for _, f := range p.Files {
		path := filepath.Join(dir, f.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, f.Data, 0600); err != nil {
			t.Fatal(err)
		}
		m.Files = append(m.Files, capsule.FileEntry{Path: f.Path})
	}
	for _, c := range Checks(dir, m) {
		if !c.Passed {
			t.Fatalf("fixture %s: %s", c.Name, c.Message)
		}
	}
	return dir, m
}

func requireFailedCheck(t *testing.T, checks []recoveryclient.Check, name string) {
	t.Helper()
	for _, c := range checks {
		if c.Name == name && !c.Passed {
			return
		}
	}
	t.Fatalf("missing failed check %q: %+v", name, checks)
}

func TestChecksRejectMalformedRecipes(t *testing.T) {
	cases := []struct {
		name   string
		recipe any
		failed string
	}{
		{"absent", nil, "Verification recipe"},
		{"non-object", []any{}, "Verification recipe"},
		{"missing tables", map[string]any{"require_any_admin": true}, "Required tables recipe"},
		{"string list", map[string]any{"required_tables": "accounts", "require_any_admin": true}, "Required tables recipe"},
		{"mixed list", map[string]any{"required_tables": []any{"accounts", 1}, "require_any_admin": true}, "Table recipe entry"},
		{"empty name", map[string]any{"required_tables": []any{""}, "require_any_admin": true}, "Table recipe entry"},
		{"omitted table", map[string]any{"required_tables": []any{"accounts", "settings"}, "require_any_admin": true}, "Recipe requires: vault_objects"},
		{"false admin", map[string]any{"required_tables": []any{"accounts", "vault_objects", "settings"}, "require_any_admin": false}, "Administrator recipe"},
		{"string admin", map[string]any{"required_tables": []any{"accounts", "vault_objects", "settings"}, "require_any_admin": "true"}, "Administrator recipe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, m := checksFixture(t)
			m.VerificationRecipe = tc.recipe
			requireFailedCheck(t, Checks(dir, m), tc.failed)
		})
	}
}

func TestChecksRejectMissingMembersAndUnsafePaths(t *testing.T) {
	t.Run("missing listed file", func(t *testing.T) {
		dir, m := checksFixture(t)
		if err := os.Remove(filepath.Join(dir, "config/deployment.key")); err != nil {
			t.Fatal(err)
		}
		requireFailedCheck(t, Checks(dir, m), "Member present: config/deployment.key")
	})
	t.Run("omitted required member", func(t *testing.T) {
		dir, m := checksFixture(t)
		m.Files = slices.DeleteFunc(m.Files, func(f capsule.FileEntry) bool { return f.Path == dbMember })
		requireFailedCheck(t, Checks(dir, m), "Required member: "+dbMember)
	})
	for _, path := range []string{"", ".", "..", "../outside", "/absolute", "config/../outside", "config//key", `config\key`, "C:/key", "bad\x00name"} {
		t.Run(fmt.Sprintf("path %q", path), func(t *testing.T) {
			dir, m := checksFixture(t)
			m.Files = append(m.Files, capsule.FileEntry{Path: path})
			requireFailedCheck(t, Checks(dir, m), "Member path: "+path)
		})
	}
	t.Run("symlink escape", func(t *testing.T) {
		dir, m := checksFixture(t)
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "file"), []byte("outside sentinel"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
			t.Fatal(err)
		}
		m.Files = append(m.Files, capsule.FileEntry{Path: "escape/file"})
		requireFailedCheck(t, Checks(dir, m), "Member present: escape/file")
	})
	t.Run("database symlink", func(t *testing.T) {
		dir, m := checksFixture(t)
		old := filepath.Join(dir, dbMember)
		other := filepath.Join(t.TempDir(), dbMember)
		if err := os.Rename(old, other); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, old); err != nil {
			t.Fatal(err)
		}
		requireFailedCheck(t, Checks(dir, m), "Database present: "+dbMember)
	})
	t.Run("missing database stays missing", func(t *testing.T) {
		dir, m := checksFixture(t)
		path := filepath.Join(dir, dbMember)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		requireFailedCheck(t, Checks(dir, m), "Database present: "+dbMember)
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("validator created database: %v", err)
		}
	})
}

func TestChecksAlwaysRequireApplicationSchemaAndAdmin(t *testing.T) {
	for _, stmt := range []string{`DROP TABLE vault_objects`, `UPDATE accounts SET status='suspended'`, `DELETE FROM accounts`} {
		t.Run(stmt, func(t *testing.T) {
			dir, m := checksFixture(t)
			uri := url.URL{Scheme: "file", Path: filepath.Join(dir, dbMember), RawQuery: "mode=rw"}
			db, err := sql.Open("sqlite", uri.String())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			// The recipe cannot remove either mandatory check.
			m.VerificationRecipe = map[string]any{"required_tables": []any{"accounts", "settings"}, "require_any_admin": false}
			name := "Active administrator"
			if strings.HasPrefix(stmt, "DROP") {
				name = "Table present: vault_objects"
			}
			requireFailedCheck(t, Checks(dir, m), name)
			if strings.HasPrefix(stmt, "DROP") {
				var n int
				if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='vault_objects'`).Scan(&n); err != nil || n != 0 {
					t.Fatalf("validator repaired schema: %d %v", n, err)
				}
			}
		})
	}
}

func TestDrillRejectsDecodedMalformedRecipeAndCleansScratch(t *testing.T) {
	st, dataDir, configDir := seed(t)
	p, err := Collect(context.Background(), st, dataDir, configDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	p.VerificationRecipe = map[string]any{"required_tables": []any{"accounts", 7}, "require_any_admin": true}
	root, err := DrillRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := recoveryclient.Drill(context.Background(), root, p, Checks)
	if err != nil {
		t.Fatal(err)
	}
	requireFailedCheck(t, res.Checks, "Table recipe entry")
	if res.Passed {
		t.Fatal("malformed recipe passed")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("drill left scratch: %v %v", entries, err)
	}
}

func TestChecksHonorAdditionalRecipeTables(t *testing.T) {
	dir, m := checksFixture(t)
	recipe := m.VerificationRecipe.(map[string]any)
	recipe["required_tables"] = append(recipe["required_tables"].([]any), "future_application_table")
	requireFailedCheck(t, Checks(dir, m), "Table present: future_application_table")
}
