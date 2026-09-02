package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Busness-app/kybookmarks-server/internal/crypto"
	"github.com/Busness-app/kybookmarks-server/internal/store"
)

func TestSecondAccountCanBeCreated(t *testing.T) {
	srv, _, cleanup := setupTestServer(t)
	defer cleanup()

	makeAccount(t, srv, "first", "admin")
	makeAccount(t, srv, "second", "user")

	count, err := srv.store.CountAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected 2 accounts, got %d", count)
	}
}

// TestSetupCannotEnrolTwoAdmins races concurrent setup calls. Password hashing
// sits between the "is anyone here yet" check and the insert, so the window is
// wide; only one request may end up with an account.
func TestSetupCannotEnrolTwoAdmins(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	const racers = 8
	var wg sync.WaitGroup
	codes := make([]int, racers)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload, _ := json.Marshal(map[string]any{
				"username":    fmt.Sprintf("admin%d", i),
				"email":       fmt.Sprintf("admin%d@example.com", i),
				"displayName": "Admin",
				"password":    "super-secure-master-password-123",
			})
			<-start
			req := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(payload))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			codes[i] = w.Code
		}(i)
	}
	close(start)
	wg.Wait()

	count, err := srv.store.CountAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("setup created %d accounts, want exactly 1 (codes: %v)", count, codes)
	}

	won := 0
	for _, c := range codes {
		if c == http.StatusOK {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d setup requests reported success, want exactly 1 (codes: %v)", won, codes)
	}
}

func TestRecoveryRefusesSuspendedAccount(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	const secret = "AAAABBBBCCCCDDDD"
	salt, err := crypto.GenerateRandomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := crypto.HashPassword(secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	acc := &store.Account{
		Username:         "suspended",
		Email:            "suspended@example.com",
		Status:           "suspended",
		Role:             "user",
		AuthSalt:         salt,
		RecoveryVerifier: verifier,
		RecoveryKeyWrap:  "wrapped-vault-key",
	}
	if err := srv.store.CreateAccount(acc); err != nil {
		t.Fatal(err)
	}

	w := post(t, handler, "/api/auth/recovery", map[string]string{
		"username":       "suspended",
		"recoverySecret": secret,
	}, nil, nil)

	if w.Code == http.StatusOK {
		t.Fatalf("suspended account recovered a session: %s", w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("wrapped-vault-key")) {
		t.Fatal("recovery leaked the vault key wrapper to a suspended account")
	}
}

func TestRecoveryLocksOutAfterRepeatedFailures(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	makeAccount(t, srv, "target", "user")

	var last int
	for i := 0; i < 4; i++ {
		w := post(t, handler, "/api/auth/recovery", map[string]string{
			"username":       "target",
			"recoverySecret": "WRONGWRONGWRONG",
		}, nil, nil)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("4th recovery attempt returned %d, want 429", last)
	}
}

// TestLoginParamsDoesNotRevealAccountExistence checks that the salt served for
// an unknown user is not a fixed constant, which would flag every real account.
func TestLoginParamsDoesNotRevealAccountExistence(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	makeAccount(t, srv, "real", "user")

	params := func(username string) string {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/login-params?username="+username, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("login-params for %q returned %d", username, w.Code)
		}
		var got struct {
			Salt string `json:"salt"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got.Salt
	}

	ghostA := params("ghost-a")
	ghostB := params("ghost-b")
	real := params("real")

	if ghostA == ghostB {
		t.Fatal("all unknown usernames share one salt, which identifies real accounts")
	}
	if ghostA != params("ghost-a") {
		t.Fatal("decoy salt is not stable across requests")
	}
	if ghostA == real || ghostB == real {
		t.Fatal("decoy salt collided with a real account salt")
	}
	if len(ghostA) != len(real) {
		t.Fatalf("decoy salt length %d differs from real salt length %d", len(ghostA), len(real))
	}
}

// TestCSRFTokenMustMatchTheSession plants a self-chosen csrf_token cookie and
// header pair. A check that only compares those two to each other accepts it.
func TestCSRFTokenMustMatchTheSession(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	acc := makeAccount(t, srv, "victim", "user")
	sess, _ := sessionFor(t, srv, acc)

	forged := &http.Cookie{Name: csrfCookieName, Value: "attacker-chosen-csrf-value"}
	w := post(t, handler, "/api/auth/key-wraps", map[string]string{
		"passwordKeyWrap": "attacker-supplied",
	}, sess, forged)

	if w.Code != http.StatusForbidden {
		t.Fatalf("request with a planted CSRF cookie returned %d, want 403", w.Code)
	}
}
