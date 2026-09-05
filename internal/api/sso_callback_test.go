package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kybookmarks-server/internal/sso"
	"github.com/Busness-app/kybookmarks-server/internal/sso/ssotest"
)

// stubIdP serves just enough OIDC for the callback: discovery, a JWKS, and a token
// endpoint returning an RS256 ID token carrying the claims the test wants to assert on,
// with the standard claims the verifier demands filled in.
func stubIdP(t *testing.T, claims map[string]any) *httptest.Server {
	t.Helper()
	key := ssotest.Key(t)
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/.well-known/jwks.json",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", ssotest.JWKS(key))
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().Unix()
		full := map[string]any{"iss": srv.URL, "aud": "kybookmarks", "nonce": "testnonce", "iat": now, "exp": now + 300}
		for k, v := range claims {
			full[k] = v
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at",
			"id_token":     ssotest.Mint(t, key, full),
			"token_type":   "Bearer",
		})
	})
	return srv
}

// ssoCallback drives the callback with a state cookie the server would have set.
func ssoCallback(t *testing.T, srv *Server, handler http.Handler, idp *httptest.Server, claims map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	srv.ssoHTTP = idp.Client()
	if err := srv.ssoStore.Save(sso.SSOSettings{
		Enabled:       true,
		IssuerURL:     idp.URL,
		ClientID:      "kybookmarks",
		AutoProvision: false,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?code=authcode&state=teststate", nil)
	req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: "teststate|verifier||testnonce"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// TestSSOWillNotAdoptAnAccountOnAnUnverifiedEmail is the takeover case: an IdP
// user sets their email to the local admin's address and signs in.
func TestSSOWillNotAdoptAnAccountOnAnUnverifiedEmail(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	admin := makeAccount(t, srv, "admin", "admin")

	idp := stubIdP(t, map[string]any{
		"sub":            "attacker-subject",
		"email":          admin.Email,
		"email_verified": false,
	})
	w := ssoCallback(t, srv, handler, idp, nil)

	if w.Code == http.StatusFound {
		t.Fatalf("unverified email claim was allowed to sign in as %s", admin.Username)
	}
	after, err := srv.store.GetAccountByID(admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SSOSubject != "" {
		t.Fatalf("admin account was bound to SSO subject %q on an unverified email", after.SSOSubject)
	}
}

// TestSSOWillNotAdoptAnAccountOnAUsernameClaim covers preferred_username, which
// most IdPs let the end user choose.
func TestSSOWillNotAdoptAnAccountOnAUsernameClaim(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	admin := makeAccount(t, srv, "admin", "admin")

	idp := stubIdP(t, map[string]any{
		"sub":                "attacker-subject",
		"preferred_username": admin.Username,
	})
	w := ssoCallback(t, srv, handler, idp, nil)

	if w.Code == http.StatusFound {
		t.Fatal("preferred_username claim was allowed to sign in as the admin")
	}
	after, err := srv.store.GetAccountByID(admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SSOSubject != "" {
		t.Fatalf("admin account was bound to SSO subject %q on a username claim", after.SSOSubject)
	}
}

// TestSSOAdoptsAnAccountOnAVerifiedEmail is the supported path, kept so the
// checks above cannot be satisfied by refusing every SSO sign-in.
func TestSSOAdoptsAnAccountOnAVerifiedEmail(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	user := makeAccount(t, srv, "employee", "user")

	idp := stubIdP(t, map[string]any{
		"sub":            "employee-subject",
		"email":          user.Email,
		"email_verified": true,
	})
	w := ssoCallback(t, srv, handler, idp, nil)

	if w.Code != http.StatusFound {
		t.Fatalf("verified email sign-in returned %d, want 302: %s", w.Code, w.Body.String())
	}
	after, err := srv.store.GetAccountByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SSOSubject != "employee-subject" {
		t.Fatalf("account not linked, sso_subject = %q", after.SSOSubject)
	}
}

// TestSSOWillNotAdoptAnAccountOnAnEmailClaimMatchingAUsername covers an IdP
// that marks a non-address attribute as verified: the claim must only ever be
// compared against the email column.
func TestSSOWillNotAdoptAnAccountOnAnEmailClaimMatchingAUsername(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	admin := makeAccount(t, srv, "admin", "admin")

	idp := stubIdP(t, map[string]any{
		"sub":            "attacker-subject",
		"email":          admin.Username,
		"email_verified": true,
	})
	w := ssoCallback(t, srv, handler, idp, nil)

	if w.Code == http.StatusFound {
		t.Fatal("email claim equal to a username was allowed to sign in as the admin")
	}
	after, err := srv.store.GetAccountByID(admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SSOSubject != "" {
		t.Fatalf("admin account was bound to SSO subject %q on a username-shaped email claim", after.SSOSubject)
	}
}

// TestSSOWillNotBindASuspendedAccount: refusing the sign-in is not enough, the
// row must stay untouched so reactivation does not hand the account over.
func TestSSOWillNotBindASuspendedAccount(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	user := makeAccount(t, srv, "former", "user")
	user.Status = "suspended"
	if err := srv.store.UpdateAccount(user); err != nil {
		t.Fatal(err)
	}

	idp := stubIdP(t, map[string]any{
		"sub":            "attacker-subject",
		"email":          user.Email,
		"email_verified": true,
	})
	w := ssoCallback(t, srv, handler, idp, nil)

	if w.Code == http.StatusFound {
		t.Fatal("suspended account was allowed to sign in via SSO")
	}
	after, err := srv.store.GetAccountByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SSOSubject != "" {
		t.Fatalf("suspended account was bound to SSO subject %q", after.SSOSubject)
	}
}

// TestSSOWillNotRebindALinkedAccount: an account already bound to one subject
// is never silently moved to another by an email match.
func TestSSOWillNotRebindALinkedAccount(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	user := makeAccount(t, srv, "employee", "user")
	user.SSOSubject = "employee-subject"
	if err := srv.store.UpdateAccount(user); err != nil {
		t.Fatal(err)
	}

	idp := stubIdP(t, map[string]any{
		"sub":            "attacker-subject",
		"email":          user.Email,
		"email_verified": true,
	})
	w := ssoCallback(t, srv, handler, idp, nil)

	if w.Code == http.StatusFound {
		t.Fatal("a different subject was allowed to sign in as an already-linked account")
	}
	after, err := srv.store.GetAccountByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SSOSubject != "employee-subject" {
		t.Fatalf("linked account was rebound to %q", after.SSOSubject)
	}
}
