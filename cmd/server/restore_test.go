package main

import (
	"bytes"
	"context"
	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/kybookmarks-server/internal/audit"
	"github.com/Busness-app/kybookmarks-server/internal/backup"
	"github.com/Busness-app/kybookmarks-server/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
)

// A capsule from another service is refused on its manifest, before any share is combined:
// the operator learns they have the wrong file without typing custodian cards.
func TestRestoreRefusesWrongServiceBeforeReadingShares(t *testing.T) {
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	payload := recoveryclient.Payload{
		ServiceName: "Other", AppVersion: "1",
		Files: []recoveryclient.File{{Path: "x.txt", Data: []byte("hello"), Mode: 0600}},
	}
	raw, _, err := recoveryclient.Seal(payload, recoveryclient.RecoveryKey{Public: k.Public(), Threshold: 2, TotalShares: 3})
	if err != nil {
		t.Fatal(err)
	}
	capsulePath := filepath.Join(t.TempDir(), "other.kycap")
	if err := os.WriteFile(capsulePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = restore(capsulePath, t.TempDir(), "KyBookmarks", nil, &out)
	if err == nil {
		t.Fatal("a capsule for another service was accepted")
	}
	if !strings.Contains(err.Error(), "Other") && !strings.Contains(err.Error(), "service") {
		t.Fatalf("error does not name the service mismatch: %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "share") {
		t.Fatalf("service check must fail before shares are considered: %v", err)
	}
}

// Exercise the product collector and restore entry point together, including the sealed
// pairing and keys a restored instance needs. All recovery material here is synthetic.
func TestRestoreCollectedInstance(t *testing.T) {
	dataDir, configDir := t.TempDir(), t.TempDir()
	st, err := store.NewStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, name := range []string{"audit.key", "enum.key", "deployment.key"} {
		if _, err := keyfile.LoadOrCreate(filepath.Join(configDir, name), 32); err != nil {
			t.Fatal(err)
		}
	}
	al, err := audit.NewLogger(filepath.Join(dataDir, "audit"), configDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := al.Log(context.Background(), "test.seed", "owner", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAccount(&store.Account{Username: "owner", Email: "owner@example.com", PasswordHash: "synthetic", AuthSalt: "00", KDFIterations: 1, Role: "admin", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("wal_canary", "restored"); err != nil {
		t.Fatal(err)
	}
	private, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	split, err := recoverykey.Split(private, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	shares := []string{split[0].String(), split[1].String()}
	key := recoveryclient.RecoveryKey{Public: private.Public(), Threshold: 2, TotalShares: 3}
	if err := recoveryclient.StoreRecoveryKey(dataDir, backup.Settings(st), key); err != nil {
		t.Fatal(err)
	}
	deployment, err := keyfile.LoadOrCreate(filepath.Join(configDir, "deployment.key"), 32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := backup.NewSealer(deployment)
	if err != nil {
		t.Fatal(err)
	}
	if err := recoveryclient.StorePairing(backup.Settings(st), sealer, "https://recovery.example.com", "synthetic-token"); err != nil {
		t.Fatal(err)
	}
	p, err := backup.Collect(context.Background(), st, dataDir, configDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := recoveryclient.Seal(p, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "test.kycap")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	var output bytes.Buffer
	if err := restore(path, target, backup.AppName, shares, &output); err != nil {
		t.Fatal(err)
	}
	for _, f := range p.Files {
		b, err := os.ReadFile(filepath.Join(target, f.Path))
		if err != nil || !bytes.Equal(b, f.Data) {
			t.Fatalf("restored member %s differs: %v", f.Path, err)
		}
		fi, err := os.Stat(filepath.Join(target, f.Path))
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("restored mode %s: %v", f.Path, err)
		}
	}
	for _, s := range shares {
		if strings.Contains(output.String(), s) {
			t.Fatal("share printed")
		}
	}
	restored, err := store.NewStore(target)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if v, err := restored.GetSetting("wal_canary"); err != nil || v != "restored" {
		t.Fatal("lost WAL canary")
	}
	restoredKey, err := keyfile.LoadOrCreate(filepath.Join(target, "config", "deployment.key"), 32)
	if err != nil {
		t.Fatal(err)
	}
	restoredSealer, err := backup.NewSealer(restoredKey)
	if err != nil {
		t.Fatal(err)
	}
	pairing, err := recoveryclient.LoadPairing(target, backup.Settings(restored), restoredSealer)
	if err != nil || pairing.Token != "synthetic-token" || pairing.Key.Public.ID() != key.Public.ID() {
		t.Fatal("restored pairing cannot open")
	}
	if _, err := audit.NewLogger(filepath.Join(target, "audit"), filepath.Join(target, "config"), ""); err != nil {
		t.Fatalf("restored audit cannot boot: %v", err)
	}
	for _, tc := range []struct {
		name, target, service string
		shares                []string
	}{{"nonempty", target, backup.AppName, shares}, {"insufficient", filepath.Join(t.TempDir(), "out"), backup.AppName, shares[:1]}, {"wrong service", filepath.Join(t.TempDir(), "out"), "Other", shares}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := restore(path, tc.target, tc.service, tc.shares, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe restore accepted")
			}
		})
	}
	wrongKey, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	wrongShares, err := recoverykey.Split(wrongKey, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(path, filepath.Join(t.TempDir(), "out"), backup.AppName, []string{wrongShares[0].String(), wrongShares[1].String()}, &bytes.Buffer{}); err == nil {
		t.Fatal("wrong ceremony shares accepted")
	}
	raw[len(raw)/2] ^= 1
	bad := filepath.Join(t.TempDir(), "bad.kycap")
	if err := os.WriteFile(bad, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restore(bad, filepath.Join(t.TempDir(), "out"), backup.AppName, shares, &bytes.Buffer{}); err == nil {
		t.Fatal("damaged capsule accepted")
	}
}
