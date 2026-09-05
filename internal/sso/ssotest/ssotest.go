// Package ssotest mints RS256 ID tokens and serves the matching JWKS, so tests in more
// than one package can stand up a KySignOn-shaped issuer. Test support only.
package ssotest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
)

// KeyID is the kid every minted token and the JWKS carry.
const KeyID = "k1"

// Key generates a signing key for one test.
func Key(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Mint signs claims as an RS256 JWT under key.
func Mint(t testing.TB, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": KeyID})
	pl, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := enc(hdr) + "." + enc(pl)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}

// JWKS serves key's public half at whatever path it is mounted on.
func JWKS(key *rsa.PrivateKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enc := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": KeyID, "alg": "RS256", "use": "sig",
			"n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}
}
