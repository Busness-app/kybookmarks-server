package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"

	"github.com/Busness-app/kybookmarks-server/internal/backup"
)

type fakeRecovery struct {
	receipt recoveryclient.Receipt
	err     error
	got     []byte
}

func (f *fakeRecovery) ClaimPairing(context.Context, string, string, string, string) (recoveryclient.PairingResult, error) {
	return recoveryclient.PairingResult{}, errors.New("not in this test")
}

func (f *fakeRecovery) Deposit(_ context.Context, _, _ string, c []byte) (recoveryclient.Receipt, error) {
	f.got = c
	return f.receipt, f.err
}

// freshPin mints a throwaway suite key and returns its public half as the pin-key route
// takes it. The private half is dropped here; the tests never open a capsule.
func freshPin(t *testing.T) string {
	t.Helper()
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Public().Bytes())
}

// backupFixture gives an admin session and everything Collect needs on disk.
func backupFixture(t *testing.T) (*Server, http.Handler, *http.Cookie, *http.Cookie, func()) {
	t.Helper()
	srv, handler, cleanup := setupTestServer(t)
	admin := makeAccount(t, srv, "admin", "admin")
	sess, csrf := sessionFor(t, srv, admin)
	for _, name := range []string{"audit.key", "deployment.key"} {
		if _, err := keyfile.LoadOrCreate(filepath.Join(srv.cfg.ConfigDir, name), 32); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(srv.cfg.ConfigDir, "audit.state"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(srv.cfg.ConfigDir, "enum.key")); err != nil {
		t.Fatal("NewServer did not mint enum.key: ", err)
	}
	// The audit logger in setupTestServer writes under tmpDir/audit already; make sure the
	// log file exists even before the first entry.
	if err := os.MkdirAll(filepath.Join(srv.cfg.DataDir, "audit"), 0700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(srv.cfg.DataDir, "audit", "audit.log")
	if _, err := os.Stat(logPath); err != nil {
		if err := os.WriteFile(logPath, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	srv.recovery = &fakeRecovery{}
	return srv, handler, sess, csrf, cleanup
}

func do(t *testing.T, handler http.Handler, method, path string, body any, sess, csrf *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(payload)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if sess != nil {
		req.AddCookie(sess)
	}
	if csrf != nil {
		req.AddCookie(csrf)
		req.Header.Set("X-CSRF-Token", csrf.Value)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func pinKey(t *testing.T, handler http.Handler, sess, csrf *http.Cookie, pub string, k, n int) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, handler, http.MethodPost, "/api/admin/backup/pin-key", map[string]any{"public_key": pub, "threshold": k, "total_shares": n}, sess, csrf)
}

func auditActions(t *testing.T, srv *Server) []string {
	t.Helper()
	entries, err := srv.audit.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Action+" "+e.Details)
	}
	return out
}

func TestPinKeyIsWriteOnce(t *testing.T) {
	_, handler, sess, csrf, cleanup := backupFixture(t)
	defer cleanup()
	a, b := freshPin(t), freshPin(t)
	if w := pinKey(t, handler, sess, csrf, a, 2, 3); w.Code != http.StatusOK {
		t.Fatalf("first pin: %d %s", w.Code, w.Body.String())
	}
	if w := pinKey(t, handler, sess, csrf, b, 2, 3); w.Code != http.StatusConflict {
		t.Fatalf("second pin with a different key: %d, want 409", w.Code)
	}
	if w := pinKey(t, handler, sess, csrf, a, 2, 3); w.Code != http.StatusOK {
		t.Fatalf("same key again: %d, want 200", w.Code)
	}
}

func TestPinKeyBadTopology(t *testing.T) {
	_, handler, sess, csrf, cleanup := backupFixture(t)
	defer cleanup()
	if w := pinKey(t, handler, sess, csrf, freshPin(t), 1, 3); w.Code != http.StatusBadRequest {
		t.Fatalf("1-of-3: %d, want 400", w.Code)
	}
}

func TestRunWithPinnedKeyAndNoDestination(t *testing.T) {
	_, handler, sess, csrf, cleanup := backupFixture(t)
	defer cleanup()
	if w := pinKey(t, handler, sess, csrf, freshPin(t), 2, 3); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	w := do(t, handler, http.MethodPost, "/api/admin/backup/deposit", nil, sess, csrf)
	if w.Code != http.StatusPreconditionFailed || !strings.Contains(w.Body.String(), "KYBOOKMARKS_BACKUP_DIR") {
		t.Fatalf("no destination: %d %s", w.Code, w.Body.String())
	}
}

func TestRunWritesLocalCopy0600(t *testing.T) {
	srv, handler, sess, csrf, cleanup := backupFixture(t)
	defer cleanup()
	srv.cfg.Backup.Dir = t.TempDir()
	if w := pinKey(t, handler, sess, csrf, freshPin(t), 2, 3); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	w := do(t, handler, http.MethodPost, "/api/admin/backup/deposit", nil, sess, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	entries, err := os.ReadDir(srv.cfg.Backup.Dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("local copies: %v %v", entries, err)
	}
	name := entries[0].Name()
	if !strings.HasPrefix(name, backup.AppName+".") || !strings.HasSuffix(name, ".kycap") {
		t.Fatalf("local copy name %q", name)
	}
	fi, _ := os.Stat(filepath.Join(srv.cfg.Backup.Dir, name))
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("local copy mode %v", fi.Mode())
	}
	found := false
	for _, a := range auditActions(t, srv) {
		if strings.HasPrefix(a, "admin.backup_run ") && strings.Contains(a, "outcome=success") {
			found = true
		}
	}
	if !found {
		t.Fatal("no admin.backup_run success in the audit chain")
	}
}

func seedPairing(t *testing.T, srv *Server) string {
	t.Helper()
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key := recoveryclient.RecoveryKey{Public: k.Public(), Threshold: 2, TotalShares: 3}
	if err := recoveryclient.StoreRecoveryKey(srv.cfg.DataDir, backup.Settings(srv.store), key); err != nil {
		t.Fatal(err)
	}
	const token = "secret-bearer-token-value"
	if err := recoveryclient.StorePairing(backup.Settings(srv.store), srv.sealer, "https://recovery.example.com", token); err != nil {
		t.Fatal(err)
	}
	return token
}

func TestUnpairKeepsPin(t *testing.T) {
	srv, handler, sess, csrf, cleanup := backupFixture(t)
	defer cleanup()
	seedPairing(t, srv)
	if w := do(t, handler, http.MethodDelete, "/api/admin/backup/pairing", nil, sess, csrf); w.Code != http.StatusOK {
		t.Fatalf("unpair: %d %s", w.Code, w.Body.String())
	}
	w := do(t, handler, http.MethodGet, "/api/admin/backup/status", nil, sess, nil)
	var st struct {
		Paired    bool `json:"paired"`
		KeyPinned bool `json:"key_pinned"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if !st.KeyPinned || st.Paired {
		t.Fatalf("after unpair: %s", w.Body.String())
	}
	if w := do(t, handler, http.MethodDelete, "/api/admin/backup/pairing", nil, sess, csrf); w.Code != http.StatusPreconditionFailed {
		t.Fatalf("second unpair: %d, want 412", w.Code)
	}
}

func TestScheduleBounds(t *testing.T) {
	srv, handler, sess, csrf, cleanup := backupFixture(t)
	defer cleanup()
	put := func(sec int64) int {
		return do(t, handler, http.MethodPut, "/api/admin/backup/schedule", map[string]any{"interval_sec": sec}, sess, csrf).Code
	}
	if c := put(0); c != http.StatusOK {
		t.Fatalf("0: %d", c)
	}
	if c := put(899); c != http.StatusBadRequest {
		t.Fatalf("899: %d", c)
	}
	if c := put(1 << 55); c != http.StatusBadRequest {
		t.Fatalf("2^55: %d", c)
	}
	if c := put(900); c != http.StatusOK {
		t.Fatalf("900: %d", c)
	}
	found := false
	for _, a := range auditActions(t, srv) {
		if strings.HasPrefix(a, "admin.backup_schedule ") && strings.Contains(a, "interval_sec=900") {
			found = true
		}
	}
	if !found {
		t.Fatal("audit row does not carry the stored interval")
	}
}

func TestStatusNeverCarriesToken(t *testing.T) {
	srv, handler, sess, _, cleanup := backupFixture(t)
	defer cleanup()
	token := seedPairing(t, srv)
	w := do(t, handler, http.MethodGet, "/api/admin/backup/status", nil, sess, nil)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, token) || strings.Contains(body, "kyrecovery_token_enc") {
		t.Fatalf("status leaks the credential: %s", body)
	}
	if !strings.Contains(body, `"paired":true`) {
		t.Fatalf("status does not report the pairing: %s", body)
	}
}

func TestExportCapsuleUnpairedIs412(t *testing.T) {
	_, handler, sess, _, cleanup := backupFixture(t)
	defer cleanup()
	if w := do(t, handler, http.MethodGet, "/api/admin/backup/export-capsule", nil, sess, nil); w.Code != http.StatusPreconditionFailed {
		t.Fatalf("export unpaired: %d", w.Code)
	}
}

func TestExportCapsuleIsASealedContainer(t *testing.T) {
	_, handler, sess, csrf, cleanup := backupFixture(t)
	defer cleanup()
	if w := pinKey(t, handler, sess, csrf, freshPin(t), 2, 3); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	w := do(t, handler, http.MethodGet, "/api/admin/backup/export-capsule", nil, sess, nil)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("export: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if bytes.Contains(w.Body.Bytes(), []byte("kybookmarks.db")) {
		t.Fatal("member names appear in the clear; the container is not sealed")
	}
}

// An export that cannot be recorded on the audit chain is refused, not served.
func TestExportCapsuleIsRefusedWhenAuditFails(t *testing.T) {
	srv, handler, sess, csrf, cleanup := backupFixture(t)
	defer cleanup()
	if w := pinKey(t, handler, sess, csrf, freshPin(t), 2, 3); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	// The collector must still read the log, so it cannot become a directory here; a
	// read-only log fails the append and nothing else. Root ignores file modes.
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	logPath := filepath.Join(srv.cfg.DataDir, "audit", "audit.log")
	if err := os.Chmod(logPath, 0400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(logPath, 0600) })
	w := do(t, handler, http.MethodGet, "/api/admin/backup/export-capsule", nil, sess, nil)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "audit_failed") {
		t.Fatalf("export with a dead audit chain: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Type") == "application/octet-stream" {
		t.Fatal("capsule bytes were served despite the refused audit record")
	}
}

func TestBackupRoutesRequireAdmin(t *testing.T) {
	srv, handler, _, _, cleanup := backupFixture(t)
	defer cleanup()
	user := makeAccount(t, srv, "someone", "user")
	usess, ucsrf := sessionFor(t, srv, user)
	routes := []struct{ method, path string }{
		{http.MethodPost, "/api/admin/backup/drill"},
		{http.MethodGet, "/api/admin/backup/export-capsule"},
		{http.MethodPost, "/api/admin/backup/pair-remote"},
		{http.MethodPost, "/api/admin/backup/deposit"},
		{http.MethodDelete, "/api/admin/backup/pairing"},
		{http.MethodPost, "/api/admin/backup/pin-key"},
		{http.MethodPut, "/api/admin/backup/schedule"},
		{http.MethodGet, "/api/admin/backup/status"},
	}
	for _, rt := range routes {
		if w := do(t, handler, rt.method, rt.path, nil, nil, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s anonymous: %d, want 401", rt.method, rt.path, w.Code)
		}
		if w := do(t, handler, rt.method, rt.path, nil, usess, ucsrf); w.Code != http.StatusForbidden {
			t.Errorf("%s %s as user: %d, want 403", rt.method, rt.path, w.Code)
		}
	}
}
