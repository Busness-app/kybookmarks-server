package backup

import (
	"context"
	"os"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

func TestChecksFailOnMissingDatabase(t *testing.T) {
	dir := t.TempDir()
	checks := Checks(recoveryclient.Payload{Files: []recoveryclient.File{{Path: dbMember}}})(dir)
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
	res, err := recoveryclient.Drill(context.Background(), root, p, Checks(p))
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
