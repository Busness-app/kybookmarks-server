package api

import (
	"net/http"
	"testing"
)

// The browser derives the verifier with PBKDF2 and posts the hex. The server must
// hash that at rest and accept the same hex back on recovery.
func TestPaperRecoveryAcceptsTheDerivedVerifier(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	const verifier = "9b7d2c4e1f0a6b5c3d8e7f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c"
	w := post(t, handler, "/api/setup", map[string]any{
		"username":         "owner",
		"email":            "owner@example.com",
		"displayName":      "Owner",
		"password":         "correct-horse-battery-staple",
		"authSecret":       "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
		"authSalt":         "00112233445566778899aabbccddeeff",
		"kdfIterations":    600000,
		"passwordKeyWrap":  "wrap-under-password",
		"recoveryKeyWrap":  "wrap-under-paper-key",
		"recoveryVerifier": verifier,
	}, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("setup returned %d: %s", w.Code, w.Body.String())
	}

	acc, err := srv.store.GetAccountByUsernameOrEmail("owner")
	if err != nil {
		t.Fatal(err)
	}
	if acc.RecoveryVerifier == verifier {
		t.Fatal("recovery verifier stored in the clear; it must be hashed like the password")
	}

	w = post(t, handler, "/api/auth/recovery", map[string]string{
		"username":       "owner",
		"recoverySecret": verifier,
	}, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("recovery with the derived verifier returned %d: %s", w.Code, w.Body.String())
	}

	w = post(t, handler, "/api/auth/recovery", map[string]string{
		"username":       "owner",
		"recoverySecret": "9b7d2c4e1f0a6b5c3d8e7f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9d",
	}, nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("recovery with a wrong verifier returned %d, want 401", w.Code)
	}
}

// Regenerating the paper key posts a fresh verifier; it gets the same treatment as setup.
func TestKeyWrapsHashesTheRecoveryVerifier(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	acc := makeAccount(t, srv, "alice", "user")
	sess, csrf := sessionFor(t, srv, acc)

	const verifier = "1111111111111111111111111111111111111111111111111111111111111111"
	w := post(t, handler, "/api/auth/key-wraps", map[string]string{
		"recoveryKeyWrap":  "wrap-under-new-paper-key",
		"recoveryVerifier": verifier,
	}, sess, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("key-wraps returned %d: %s", w.Code, w.Body.String())
	}

	stored, err := srv.store.GetAccountByUsernameOrEmail("alice")
	if err != nil {
		t.Fatal(err)
	}
	if stored.RecoveryVerifier == "" || stored.RecoveryVerifier == verifier {
		t.Fatalf("key-wraps stored the verifier in the clear: %q", stored.RecoveryVerifier)
	}

	w = post(t, handler, "/api/auth/recovery", map[string]string{
		"username":       "alice",
		"recoverySecret": verifier,
	}, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("recovery after key-wraps returned %d: %s", w.Code, w.Body.String())
	}
}
