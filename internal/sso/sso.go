package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Busness-app/ky-primitives/oidcverify"
)

// SSOSettings holds the OpenID Connect configuration.
type SSOSettings struct {
	Enabled       bool   `json:"enabled"`
	IssuerURL     string `json:"issuerUrl"`
	ClientID      string `json:"clientId"`
	ClientSecret  string `json:"clientSecret,omitempty"`
	RedirectURI   string `json:"redirectUri,omitempty"`
	AutoProvision bool   `json:"autoProvision"`
}

// Store manages the persistence of SSOSettings to sso.json.
type Store struct {
	mu       sync.RWMutex
	filePath string
	settings SSOSettings
}

// NewStore initializes a new Store with settings loaded from configDir/sso.json.
func NewStore(configDir string) *Store {
	filePath := filepath.Join(configDir, "sso.json")
	s := &Store{filePath: filePath}
	_ = s.loadFromDisk()
	return s
}

func (s *Store) loadFromDisk() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	var settings SSOSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return err
	}
	s.settings = settings
	return nil
}

// Load returns the current SSOSettings.
func (s *Store) Load() SSOSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

// Save persists new SSOSettings to disk.
func (s *Store) Save(settings SSOSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(s.filePath, data, 0600); err != nil {
		return err
	}
	s.settings = settings
	return nil
}

// DiscoveryDoc represents the OpenID Provider Configuration document.
type DiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// httpClient is the client the issuer is reached with: the caller's, or a bounded default.
func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// DiscoverEndpoints fetches the OpenID configuration from the issuer URL.
func DiscoverEndpoints(ctx context.Context, client *http.Client, issuerURL string) (*DiscoveryDoc, error) {
	issuerURL = strings.TrimRight(issuerURL, "/")
	wellKnown := issuerURL + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := httpClient(client).Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned HTTP %d", resp.StatusCode)
	}

	var doc DiscoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	return &doc, nil
}

// GeneratePKCE creates a code_verifier and code_challenge (S256).
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// TokenResponse represents the token response from the authorization server.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ExchangeCode exchanges an authorization code for tokens.
func ExchangeCode(ctx context.Context, client *http.Client, tokenEndpoint, clientID, clientSecret, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient(client).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var tok TokenResponse
	if err := json.Unmarshal(bodyBytes, &tok); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tok, nil
}

// Claims represents standard OpenID Connect claims.
type Claims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Username      string `json:"preferred_username"`
	Role          string `json:"role"`
}

// NewVerifier builds a JWKS-backed verifier for one issuer and this client. Callers keep it
// alive across logins so the JWKS cache and its refresh rate limit do their job. A nil
// client means the lib's default.
func NewVerifier(issuer, clientID string, client *http.Client) *oidcverify.Verifier {
	return &oidcverify.Verifier{Issuer: issuer, Audience: clientID, HTTPClient: client}
}

// VerifiedClaims checks the ID token's signature, issuer, audience, lifetime and nonce, then
// reads the profile claims from it. Userinfo may fill a missing email or name and must
// report the same subject; it is never the source of identity.
func VerifiedClaims(ctx context.Context, v *oidcverify.Verifier, idToken, nonce, accessToken, userinfoEndpoint string) (*Claims, error) {
	if idToken == "" {
		return nil, errors.New("identity provider returned no ID token")
	}
	vc, err := v.VerifyWithNonce(ctx, idToken, nonce)
	if err != nil {
		return nil, err
	}
	claims := &Claims{
		Subject:  vc.Subject,
		Email:    vc.String("email"),
		Name:     vc.String("name"),
		Username: vc.String("preferred_username"),
		Role:     vc.String("role"),
	}
	if raw, ok := vc.Raw["email_verified"]; ok {
		_ = json.Unmarshal(raw, &claims.EmailVerified)
	}

	if (claims.Email == "" || claims.Name == "") && userinfoEndpoint != "" && accessToken != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+accessToken)
			resp, err := httpClient(v.HTTPClient).Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				var u Claims
				if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&u) == nil && u.Subject == claims.Subject {
					if claims.Email == "" {
						// Verification travels with the address it describes.
						claims.Email, claims.EmailVerified = u.Email, u.EmailVerified
					}
					if claims.Name == "" {
						claims.Name = u.Name
					}
				}
			}
		}
	}

	if claims.Username == "" {
		if claims.Email != "" {
			claims.Username = strings.Split(claims.Email, "@")[0]
		} else {
			claims.Username = claims.Subject
		}
	}

	return claims, nil
}

// StateCookie generates an encrypted or hex-encoded state parameter.
func GenerateState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
