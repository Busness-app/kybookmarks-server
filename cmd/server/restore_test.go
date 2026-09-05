package main

import (
	"bytes"
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
