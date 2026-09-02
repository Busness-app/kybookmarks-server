package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busness-app/kybookmarks-server/internal/sso"
)

// stubIdP serves just enough OIDC for the callback: discovery, plus a token
// endpoint returning an ID token carrying the claims the test wants to assert on.
func stubIdP(t *testing.T, claims map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		payload, _ := json.Marshal(claims)
		idToken := fmt.Sprintf("%s.%s.%s",
			base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)),
			base64.RawURLEncoding.EncodeToString(payload),
			base64.RawURLEncoding.EncodeToString([]byte("signature")),
		)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at",
			"id_token":     idToken,
			"token_type":   "Bearer",
		})
	})
	return srv
}

// ssoCallback drives the callback with a state cookie the server would have set.
func ssoCallback(t *testing.T, srv *Server, handler http.Handler, idp *httptest.Server, claims map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	if err := srv.ssoStore.Save(sso.SSOSettings{
		Enabled:       true,
		IssuerURL:     idp.URL,
		ClientID:      "kybookmarks",
		AutoProvision: false,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?code=authcode&state=teststate", nil)
	req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: "teststate|verifier|"})
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
