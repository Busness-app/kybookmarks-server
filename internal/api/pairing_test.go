package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

// makeAccount inserts an account directly so tests can build multi-user scenarios
// without going through setup, which only ever creates the first admin.
func makeAccount(t *testing.T, srv *Server, username, role string) *store.Account {
	t.Helper()
	acc := &store.Account{
		Username: username,
		Email:    username + "@example.com",
		Role:     role,
		Status:   "active",
		AuthSalt: "00000000000000000000000000000000",
	}
	if err := srv.store.CreateAccount(acc); err != nil {
		t.Fatalf("create %s: %v", username, err)
	}
	return acc
}

// sessionFor mints a real session for an account and returns its cookies.
func sessionFor(t *testing.T, srv *Server, acc *store.Account) (*http.Cookie, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := srv.startSession(w, r, acc.ID, ""); err != nil {
		t.Fatalf("start session for %s: %v", acc.Username, err)
	}
	var sess, csrf *http.Cookie
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case sessionCookieName:
			sess = c
		case csrfCookieName:
			csrf = c
		}
	}
	if sess == nil || csrf == nil {
		t.Fatalf("startSession did not set both cookies for %s", acc.Username)
	}
	return sess, csrf
}

// post issues a JSON POST, attaching the given cookies and matching CSRF header.
func post(t *testing.T, handler http.Handler, path string, body any, sess, csrf *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
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

func TestPairRequestRequiresAuth(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	victim := makeAccount(t, srv, "victim", "admin")

	w := post(t, handler, "/api/devices/pair/request", map[string]string{
		"userId":     victim.ID,
		"deviceName": "attacker device",
	}, nil, nil)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated pair/request returned %d, want 401: %s", w.Code, w.Body.String())
	}
}

func TestPairRequestIgnoresBodyUserID(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	victim := makeAccount(t, srv, "victim", "admin")
	attacker := makeAccount(t, srv, "attacker", "user")
	sess, csrf := sessionFor(t, srv, attacker)

	w := post(t, handler, "/api/devices/pair/request", map[string]string{
		"userId":     victim.ID,
		"deviceName": "attacker device",
	}, sess, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated pair/request returned %d: %s", w.Code, w.Body.String())
	}

	var got store.PairingSession
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.UserID != attacker.ID {
		t.Fatalf("pairing session bound to %q, want the caller %q", got.UserID, attacker.ID)
	}
}

func TestApprovalCannotCrossAccounts(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	victim := makeAccount(t, srv, "victim", "admin")
	attacker := makeAccount(t, srv, "attacker", "user")

	// A pairing session that belongs to the victim.
	pending, err := srv.devices.RequestPairing(victim.ID, "victim laptop", "browser_chrome")
	if err != nil {
		t.Fatal(err)
	}

	sess, csrf := sessionFor(t, srv, attacker)
	w := post(t, handler, "/api/devices/pair/approve", map[string]string{
		"pin":              pending.PIN,
		"vaultKeyEnvelope": "attacker-supplied-envelope",
	}, sess, csrf)

	if w.Code == http.StatusOK {
		t.Fatal("attacker approved a pairing session belonging to another account")
	}
}

// TestPairingCannotEscalateToAnotherAccount walks the whole chain an attacker
// would use: mint a pairing session naming the victim, approve it with their own
// account, then redeem it. Success would hand them a session as the victim.
func TestPairingCannotEscalateToAnotherAccount(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	victim := makeAccount(t, srv, "victim", "admin")
	attacker := makeAccount(t, srv, "attacker", "user")
	sess, csrf := sessionFor(t, srv, attacker)

	w := post(t, handler, "/api/devices/pair/request", map[string]string{
		"userId":     victim.ID,
		"deviceName": "attacker device",
	}, sess, csrf)
	if w.Code != http.StatusOK {
		t.Skipf("pair/request rejected (%d), chain cannot start", w.Code)
	}
	var pending store.PairingSession
	if err := json.Unmarshal(w.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}

	w = post(t, handler, "/api/devices/pair/approve", map[string]string{
		"pin":              pending.PIN,
		"vaultKeyEnvelope": "attacker-supplied-envelope",
	}, sess, csrf)
	if w.Code != http.StatusOK {
		return // approval refused: the chain is broken here, which is the point
	}

	w = post(t, handler, "/api/devices/pair/redeem", map[string]string{
		"pairingToken": pending.PairingToken,
		"publicKey":    "attacker-device-public-key",
	}, nil, nil)
	if w.Code != http.StatusOK {
		return
	}

	// A session came back. It must not belong to the victim.
	var redeemed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &redeemed); err != nil {
		t.Fatal(err)
	}
	if redeemed.Token == "" {
		return
	}
	stored, err := srv.store.GetSession(hashToken(redeemed.Token))
	if err != nil {
		t.Fatalf("redeem returned a token with no session: %v", err)
	}
	if stored.UserID == victim.ID {
		t.Fatal("privilege escalation: pairing handed the attacker a session as the victim admin")
	}
}
