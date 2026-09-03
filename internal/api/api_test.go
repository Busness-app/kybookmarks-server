package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/kybookmarks-server/internal/audit"
	"github.com/Busness-app/kybookmarks-server/internal/devices"
	"github.com/Busness-app/kybookmarks-server/internal/sso"
	"github.com/Busness-app/kybookmarks-server/internal/store"
	"github.com/Busness-app/kybookmarks-server/internal/vault"
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
	al, err := audit.NewLogger(filepath.Join(tmpDir, "audit"), filepath.Join(tmpDir, "auditconf"), "")
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		DataDir:    tmpDir,
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
		"deviceName": "Chrome Browser Extension",
		"deviceType": "browser_chrome",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/devices/pair/request", bytes.NewReader(pairReqPayload))
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("pair request failed: %d - %s", w.Code, w.Body.String())
	}
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
	var auditResp struct {
		Valid bool
		Count int
	}
	_ = json.Unmarshal(w.Body.Bytes(), &auditResp)
	if !auditResp.Valid || auditResp.Count == 0 {
		t.Fatalf("audit verify failed: %+v", auditResp)
	}
}

// syncRequest posts a directory-sync event, optionally signing it.
func syncRequest(t *testing.T, handler http.Handler, secret, body string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/sync/events", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(body))
		req.Header.Set("X-KySignOn-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code
}

func TestDirectorySyncRequiresSignature(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	const body = `{"action":"user.create","user":{"id":"sso-1","username":"mallory","role":"admin"}}`

	// An unsigned request must not be trusted. Omitting the header is the whole attack.
	if code := syncRequest(t, handler, "", body); code != http.StatusUnauthorized {
		t.Errorf("unsigned sync event: got %d, want 401", code)
	}
	if acc, _ := srv.store.GetAccountByUsernameOrEmail("mallory"); acc != nil {
		t.Fatal("unsigned sync event created an admin account")
	}

	if code := syncRequest(t, handler, "wrong-secret", body); code != http.StatusUnauthorized {
		t.Errorf("badly signed sync event: got %d, want 401", code)
	}
	if acc, _ := srv.store.GetAccountByUsernameOrEmail("mallory"); acc != nil {
		t.Fatal("badly signed sync event created an admin account")
	}

	if code := syncRequest(t, handler, "test-sync-secret", body); code != http.StatusOK {
		t.Fatalf("correctly signed sync event: got %d, want 200", code)
	}
	if acc, _ := srv.store.GetAccountByUsernameOrEmail("mallory"); acc == nil {
		t.Fatal("correctly signed sync event did not replicate the user")
	}
}

// A server with no sync secret must fail closed, not accept everything.
func TestDirectorySyncFailsClosedWithoutSecret(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()
	srv.cfg.SyncSecret = ""

	const body = `{"action":"user.create","user":{"id":"sso-2","username":"nobody","role":"admin"}}`
	if code := syncRequest(t, handler, "", body); code != http.StatusUnauthorized {
		t.Errorf("sync event with no configured secret: got %d, want 401", code)
	}
	if acc, _ := srv.store.GetAccountByUsernameOrEmail("nobody"); acc != nil {
		t.Fatal("sync event was applied with no secret configured")
	}
}

// A client that aborts its connection must not be able to suppress the record of what
// it just did. r.Context() dies with the connection, so if Log honoured it a
// brute-forcing client could drop every auth.login_failed simply by hanging up.
func TestAbortedRequestStillAudits(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	before, err := srv.audit.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{"username": "nobody", "password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	ctx, cancel := context.WithCancel(req.Context())
	cancel() // the client hung up before the handler reached its audit call
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login: got %d, want 401", w.Code)
	}

	after, err := srv.audit.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("aborted request suppressed its audit record: %d entries before, %d after", len(before), len(after))
	}
	if got := after[len(after)-1].Action; got != "auth.login_failed" {
		t.Fatalf("last audit action = %q, want auth.login_failed", got)
	}
}

// An audit write that fails must not vanish. Every call site used to be `_, _ =`, so a
// full or read-only audit volume erased auth.login_failed, admin.user_deleted and
// devices.paired while the request returned its normal status and nothing reached the
// server log -- the same suppression Log's context handling exists to prevent, reached
// through the filesystem instead of a dropped connection.
func TestAuditWriteFailureIsNotSilent(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	// Make the audit log unwritable in a way root cannot ignore: put a directory where
	// the log file goes, so O_WRONLY fails with EISDIR whatever the uid.
	if err := os.MkdirAll(filepath.Join(srv.cfg.DataDir, "audit", "audit.log"), 0700); err != nil {
		t.Fatal(err)
	}

	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	body, _ := json.Marshal(map[string]string{"username": "nobody", "password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// The request is deliberately unaffected: the action has already happened, so a 500
	// would neither undo it nor restore the record.
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login: got %d, want 401", w.Code)
	}

	if !strings.Contains(logged.String(), "auth.login_failed") {
		t.Fatalf("a failed audit write reached no operator: server log held %q", logged.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var health struct {
		Status             string `json:"status"`
		AuditWriteFailures uint64 `json:"auditWriteFailures"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health.Status != "degraded" || health.AuditWriteFailures == 0 {
		t.Fatalf("health reported status=%q failures=%d after a failed audit write",
			health.Status, health.AuditWriteFailures)
	}
}
