package api

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kybookmarks-server/internal/sso/ssotest"
	"github.com/Busness-app/kybookmarks-server/internal/store"
)

// ssoLogin signs the account in through the callback and returns its session cookie.
// claims is the live map the issuer reads at token time, so a test changes it between logins.
func ssoLogin(t *testing.T, srv *Server, handler http.Handler, idp *httptest.Server, claims map[string]any, acc *store.Account, sid string) *http.Cookie {
	t.Helper()
	claims["sub"], claims["sid"], claims["email"], claims["email_verified"] = acc.Username+"-subject", sid, acc.Email, true
	w := ssoCallback(t, srv, handler, idp, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("login %s/%s = %d: %s", acc.Username, sid, w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			return c
		}
	}
	t.Fatalf("login %s/%s set no session cookie", acc.Username, sid)
	return nil
}

// logoutToken mints a logout token the way KySignOn would; over overrides or removes (nil) claims.
func logoutToken(t *testing.T, key *rsa.PrivateKey, issuer string, over map[string]any) string {
	t.Helper()
	now := time.Now().Unix()
	full := map[string]any{
		"iss": issuer, "aud": "kybookmarks", "iat": now, "exp": now + 120,
		"jti":    "jti-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", ""),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	typ := "logout+jwt"
	for k, v := range over {
		switch {
		case k == "typ":
			typ = v.(string)
		case v == nil:
			delete(full, k)
		default:
			full[k] = v
		}
	}
	return ssotest.MintTyped(t, key, typ, full)
}

func postLogout(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/oidc/backchannel-logout", strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func alive(t *testing.T, srv *Server, c *http.Cookie) bool {
	t.Helper()
	_, err := srv.store.GetSession(hashToken(c.Value))
	return err == nil
}

func TestSSOLogoutScopesToSessionOrSubject(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()
	claims := map[string]any{}
	idp, key := stubIssuer(t, claims)
	u1, u2 := makeAccount(t, srv, "u1", "user"), makeAccount(t, srv, "u2", "user")

	s1 := ssoLogin(t, srv, handler, idp, claims, u1, "sid-1")
	s2 := ssoLogin(t, srv, handler, idp, claims, u1, "sid-2")
	other := ssoLogin(t, srv, handler, idp, claims, u2, "sid-3")
	local, _ := sessionFor(t, srv, u1)
	all := []*http.Cookie{s1, s2, other, local}

	expect := func(step string, want ...bool) {
		t.Helper()
		for i, c := range all {
			if alive(t, srv, c) != want[i] {
				t.Fatalf("%s: session %d alive=%v, want %v", step, i, !want[i], want[i])
			}
		}
	}

	if w := postLogout(handler, logoutToken(t, key, idp.URL, map[string]any{"sid": "never-issued"})); w.Code != 200 {
		t.Fatalf("unknown sid = %d, want 200 (idempotent): %s", w.Code, w.Body.String())
	}
	expect("unknown sid", true, true, true, true)

	if w := postLogout(handler, logoutToken(t, key, idp.URL, map[string]any{"sid": "sid-1", "sub": "u2-subject"})); w.Code != 200 {
		t.Fatalf("mismatched sub = %d", w.Code)
	}
	expect("sid with wrong subject", true, true, true, true)

	if w := postLogout(handler, logoutToken(t, key, idp.URL, map[string]any{"sid": "sid-1", "sub": "u1-subject"})); w.Code != 200 {
		t.Fatalf("sid logout = %d: %s", w.Code, w.Body.String())
	}
	expect("sid logout", false, true, true, true)

	if w := postLogout(handler, logoutToken(t, key, idp.URL, map[string]any{"sub": "u1-subject"})); w.Code != 200 {
		t.Fatalf("subject logout = %d: %s", w.Code, w.Body.String())
	}
	expect("subject logout", false, false, true, true)

	if acc, err := srv.store.GetAccountByID(u1.ID); err != nil || acc.SSOSubject != "u1-subject" {
		t.Fatalf("logout touched the account record: %+v %v", acc, err)
	}
}

func TestSSOLogoutRefusesReplay(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()
	claims := map[string]any{}
	idp, key := stubIssuer(t, claims)
	u1 := makeAccount(t, srv, "u1", "user")
	ssoLogin(t, srv, handler, idp, claims, u1, "sid-1")

	tok := logoutToken(t, key, idp.URL, map[string]any{"sid": "sid-1"})
	if w := postLogout(handler, tok); w.Code != 200 {
		t.Fatalf("first delivery = %d", w.Code)
	}
	again := ssoLogin(t, srv, handler, idp, claims, u1, "sid-1-again")
	if w := postLogout(handler, tok); w.Code != 400 {
		t.Fatalf("replay = %d, want 400", w.Code)
	}
	if !alive(t, srv, again) {
		t.Fatal("replayed token revoked a later session")
	}
}

func TestSSOLogoutFencesAPendingLogin(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()
	claims := map[string]any{}
	idp, key := stubIssuer(t, claims)
	u1 := makeAccount(t, srv, "u1", "user")
	ssoLogin(t, srv, handler, idp, claims, u1, "sid-0") // links the account

	for name, over := range map[string]map[string]any{
		"session": {"sid": "sid-pending"},
		"subject": {"sub": "u1-subject"},
	} {
		t.Run(name, func(t *testing.T) {
			if w := postLogout(handler, logoutToken(t, key, idp.URL, over)); w.Code != 200 {
				t.Fatalf("logout = %d", w.Code)
			}
			claims["sub"], claims["sid"], claims["email"], claims["email_verified"] = "u1-subject", "sid-pending", u1.Email, true
			w := ssoCallback(t, srv, handler, idp, nil)
			if w.Code != http.StatusForbidden {
				t.Fatalf("callback after logout = %d, want 403: %s", w.Code, w.Body.String())
			}
			for _, c := range w.Result().Cookies() {
				if c.Name == sessionCookieName && c.Value != "" {
					t.Fatal("fenced callback still set a session cookie")
				}
			}
		})
	}

	// A login the issuer performed after the subject logout is not fenced.
	claims["iat"] = time.Now().Unix() + 2
	if c := ssoLogin(t, srv, handler, idp, claims, u1, "sid-new"); !alive(t, srv, c) {
		t.Fatal("later login not alive")
	}
}

func TestSSOLogoutRejectsInvalidDeliveries(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()
	claims := map[string]any{}
	idp, key := stubIssuer(t, claims)
	u1 := makeAccount(t, srv, "u1", "user")
	sess := ssoLogin(t, srv, handler, idp, claims, u1, "sid-1")
	good := map[string]any{"sid": "sid-1", "sub": "u1-subject"}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	otherKey := ssotest.Key(t)

	bad := map[string]*httptest.ResponseRecorder{
		"id token typ":  postLogout(handler, logoutToken(t, key, idp.URL, with(map[string]any{"typ": "JWT"}))),
		"nonce present": postLogout(handler, logoutToken(t, key, idp.URL, with(map[string]any{"nonce": "n"}))),
		"no events":     postLogout(handler, logoutToken(t, key, idp.URL, with(map[string]any{"events": nil}))),
		"no jti":        postLogout(handler, logoutToken(t, key, idp.URL, with(map[string]any{"jti": nil}))),
		"wrong aud":     postLogout(handler, logoutToken(t, key, idp.URL, with(map[string]any{"aud": "other"}))),
		"wrong iss":     postLogout(handler, logoutToken(t, key, "https://other.example", good)),
		"wrong key":     postLogout(handler, logoutToken(t, otherKey, idp.URL, good)),
		"expired":       postLogout(handler, logoutToken(t, key, idp.URL, with(map[string]any{"iat": time.Now().Unix() - 3600, "exp": time.Now().Unix() - 3000}))),
	}
	tok := logoutToken(t, key, idp.URL, good)
	q := httptest.NewRequest(http.MethodPost, "/api/auth/oidc/backchannel-logout?logout_token="+url.QueryEscape(tok), nil)
	q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, q)
	bad["token in query"] = w

	two := httptest.NewRequest(http.MethodPost, "/api/auth/oidc/backchannel-logout", strings.NewReader(url.Values{"logout_token": {tok, tok}}.Encode()))
	two.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, two)
	bad["two tokens"] = w

	js := httptest.NewRequest(http.MethodPost, "/api/auth/oidc/backchannel-logout", strings.NewReader(`{"logout_token":"`+tok+`"}`))
	js.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, js)
	bad["json body"] = w

	big := httptest.NewRequest(http.MethodPost, "/api/auth/oidc/backchannel-logout", strings.NewReader("logout_token="+strings.Repeat("a", ssoLogoutBodyLimit+1)))
	big.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, big)
	bad["oversized"] = w

	for name, w := range bad {
		if w.Code < 400 {
			t.Errorf("%s: %d, want >= 400", name, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: missing no-store", name)
		}
	}
	if !alive(t, srv, sess) {
		t.Fatal("an invalid delivery revoked the session")
	}
	if w := postLogout(handler, tok); w.Code != 200 {
		t.Fatalf("the valid token should still work: %d %s", w.Code, w.Body.String())
	}
}

func TestSSOLoginRequiresSidWhenIssuerSupportsSessionLogout(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()
	u1 := makeAccount(t, srv, "u1", "user")
	idp := stubIdP(t, map[string]any{"sub": "u1-subject", "sid": "", "email": u1.Email, "email_verified": true})
	w := ssoCallback(t, srv, handler, idp, nil)
	if w.Code == http.StatusFound {
		t.Fatal("login without a sid was accepted from an issuer that promises one")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Fatal("session cookie set")
		}
	}
}
