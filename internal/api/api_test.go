package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kybookmarks-server/internal/audit"
	"kybookmarks-server/internal/devices"
	"kybookmarks-server/internal/sso"
	"kybookmarks-server/internal/store"
	"kybookmarks-server/internal/vault"
)

func setupTestServer(t *testing.T) (*Server, http.Handler, func()) {
	tmpDir, err := os.MkdirTemp("", "api-test-*")
	if err != nil {
		t.Fatal(err)
	}

	dbStore, err := store.NewStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	vm := vault.NewManager(dbStore)
	ds := devices.NewStore(dbStore)
	ss := sso.NewStore(filepath.Join(tmpDir, "config"))
	al, err := audit.NewLogger(filepath.Join(tmpDir, "audit"), "test-secret")
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		DataDir:    tmpDir,
		HMACSecret: "test-secret",
		SyncSecret: "test-sync-secret",
	}

	srv := NewServer(dbStore, vm, ds, ss, al, cfg)
	handler := srv.Routes()

	cleanup := func() {
		dbStore.Close()
		os.RemoveAll(tmpDir)
	}

	return srv, handler, cleanup
}

func TestE2EAPIWorkflows(t *testing.T) {
	_, handler, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Health check
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 health, got %d", w.Code)
	}

	// 2. Setup check (needsSetup should be true)
	req = httptest.NewRequest(http.MethodGet, "/api/setup", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var setupCheck struct{ NeedsSetup bool }
	_ = json.Unmarshal(w.Body.Bytes(), &setupCheck)
	if !setupCheck.NeedsSetup {
		t.Fatal("expected needsSetup=true")
	}

	// 3. Setup init (create admin)
	initPayload, _ := json.Marshal(map[string]any{
		"username":        "admin",
		"email":           "admin@example.com",
		"displayName":     "Admin User",
		"password":        "super-secure-master-password-123",
		"passwordKeyWrap": "enc-vault-key-under-master-pass",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(initPayload))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("setup init failed: %d - %s", w.Code, w.Body.String())
	}

	// Extract session cookie and CSRF cookie
	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
		}
		if c.Name == csrfCookieName {
			csrfCookie = c
		}
	}
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatal("expected session and csrf cookies")
	}

	// 4. Me endpoint
	req = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("me endpoint failed: %d", w.Code)
	}

	// 5. Vault sync create bookmark
	syncPayload, _ := json.Marshal(store.SyncRequest{
		KnownVersions: map[string]int64{},
		Changes: []store.VaultObject{
			{
				ObjectID:        "bm-100",
				ObjectType:      "bookmark",
				Version:         1,
				Ciphertext:      "enc-bookmark-payload",
				Nonce:           "n-100",
				KeyWrapper:      "kw-100",
				ProtocolVersion: 1,
			},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/vault/sync", bytes.NewReader(syncPayload))
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("vault sync failed: %d - %s", w.Code, w.Body.String())
	}

	// 6. Get vault objects
	req = httptest.NewRequest(http.MethodGet, "/api/vault/objects", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get vault objects failed: %d", w.Code)
	}
	var getResp struct{ Objects []store.VaultObject }
	_ = json.Unmarshal(w.Body.Bytes(), &getResp)
	if len(getResp.Objects) != 1 || getResp.Objects[0].ObjectID != "bm-100" {
		t.Fatalf("unexpected objects: %v", getResp.Objects)
	}

	// 7. Device pairing workflow
	pairReqPayload, _ := json.Marshal(map[string]string{
		"userId":     "admin",
		"deviceName": "Chrome Browser Extension",
		"deviceType": "browser_chrome",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/devices/pair/request", bytes.NewReader(pairReqPayload))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var pairSess store.PairingSession
	_ = json.Unmarshal(w.Body.Bytes(), &pairSess)
	if len(pairSess.PIN) != 6 {
		t.Fatalf("unexpected PIN: %s", pairSess.PIN)
	}

	// Approve pairing
	approvePayload, _ := json.Marshal(map[string]string{
		"pin":              pairSess.PIN,
		"vaultKeyEnvelope": "device-wrapped-vault-key",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/devices/pair/approve", bytes.NewReader(approvePayload))
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("approve pairing failed: %d - %s", w.Code, w.Body.String())
	}

	// Redeem pairing
	redeemPayload, _ := json.Marshal(map[string]string{
		"pairingToken": pairSess.PairingToken,
		"publicKey":    "client-device-public-key",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/devices/pair/redeem", bytes.NewReader(redeemPayload))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("redeem pairing failed: %d - %s", w.Code, w.Body.String())
	}

	// 8. Verify audit logs
	req = httptest.NewRequest(http.MethodPost, "/api/admin/audit/verify", nil)
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("audit verify failed: %d - %s", w.Code, w.Body.String())
	}
	var auditResp struct{ Valid bool; Count int }
	_ = json.Unmarshal(w.Body.Bytes(), &auditResp)
	if !auditResp.Valid || auditResp.Count == 0 {
		t.Fatalf("audit verify failed: %+v", auditResp)
	}
}
