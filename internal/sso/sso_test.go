package sso

import (
	"os"
	"testing"
)

func TestSSOPKCEAndSettings(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil || len(verifier) == 0 || len(challenge) == 0 {
		t.Fatalf("failed to generate PKCE: %v", err)
	}

	tmpDir, _ := os.MkdirTemp("", "sso-test-*")
	defer os.RemoveAll(tmpDir)

	store := NewStore(tmpDir)
	settings := SSOSettings{
		Enabled:   true,
		IssuerURL: "https://auth.urlxl.com",
		ClientID:  "kybookmarks",
	}
	if err := store.Save(settings); err != nil {
		t.Fatal(err)
	}
	loaded := store.Load()
	if !loaded.Enabled || loaded.ClientID != "kybookmarks" {
		t.Fatalf("failed to load saved settings: %+v", loaded)
	}
}
