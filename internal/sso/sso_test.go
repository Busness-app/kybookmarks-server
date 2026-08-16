package sso

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestSSOPKCEAndClaims(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil || len(verifier) == 0 || len(challenge) == 0 {
		t.Fatalf("failed to generate PKCE: %v", err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claimsJSON, _ := json.Marshal(map[string]any{
		"sub":                "kysignon-user-123",
		"email":              "alice@example.com",
		"name":               "Alice Admin",
		"preferred_username": "alice",
		"role":               "admin",
	})
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	fakeJWT := header + "." + payload + ".fakesig"

	claims, err := ParseClaims(context.Background(), fakeJWT, "", "")
	if err != nil {
		t.Fatalf("failed to parse claims: %v", err)
	}
	if claims.Subject != "kysignon-user-123" || claims.Username != "alice" {
		t.Fatalf("unexpected parsed claims: %+v", claims)
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
