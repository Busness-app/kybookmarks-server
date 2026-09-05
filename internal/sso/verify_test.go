package sso

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kybookmarks-server/internal/sso/ssotest"
)

func TestVerifiedClaimsAcceptsAGoodTokenAndRefusesAlgNone(t *testing.T) {
	key := ssotest.Key(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", ssotest.JWKS(key))
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	v := NewVerifier(srv.URL, "kybookmarks", srv.Client())
	now := time.Now().Unix()
	good := ssotest.Mint(t, key, map[string]any{
		"iss": srv.URL, "aud": "kybookmarks", "sub": "user-1", "nonce": "n1",
		"email": "u@example.com", "email_verified": true, "preferred_username": "u", "role": "admin",
		"iat": now, "exp": now + 300,
	})
	claims, err := VerifiedClaims(context.Background(), v, good, "n1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" || claims.Email != "u@example.com" || !claims.EmailVerified || claims.Role != "admin" || claims.Username != "u" {
		t.Fatalf("claims: %+v", claims)
	}

	if _, err := VerifiedClaims(context.Background(), v, good, "other-nonce", "", ""); err == nil {
		t.Fatal("wrong nonce accepted")
	}

	parts := strings.Split(good, ".")
	hdr, _ := json.Marshal(map[string]string{"alg": "none"})
	none := base64.RawURLEncoding.EncodeToString(hdr) + "." + parts[1] + "."
	if _, err := VerifiedClaims(context.Background(), v, none, "n1", "", ""); err == nil {
		t.Fatal("alg=none accepted; this is the bug the package exists to remove")
	}

	if _, err := VerifiedClaims(context.Background(), v, "", "n1", "", ""); err == nil {
		t.Fatal("an empty ID token must not fall through to userinfo")
	}
}
