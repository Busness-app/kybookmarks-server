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

// DiscoverEndpoints fetches the OpenID configuration from the issuer URL.
func DiscoverEndpoints(ctx context.Context, issuerURL string) (*DiscoveryDoc, error) {
	issuerURL = strings.TrimRight(issuerURL, "/")
	wellKnown := issuerURL + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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
func ExchangeCode(ctx context.Context, tokenEndpoint, clientID, clientSecret, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
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

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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

// ParseClaims parses claims from an ID token (unverified JWS payload) or userinfo endpoint.
func ParseClaims(ctx context.Context, idToken, accessToken, userinfoEndpoint string) (*Claims, error) {
	var claims Claims

	if idToken != "" {
		parts := strings.Split(idToken, ".")
		if len(parts) >= 2 {
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				_ = json.Unmarshal(payload, &claims)
			}
		}
	}

	// If missing critical claims and userinfo endpoint is available, query userinfo
	if (claims.Subject == "" || claims.Email == "") && userinfoEndpoint != "" && accessToken != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+accessToken)
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				var uClaims Claims
				if err := json.NewDecoder(resp.Body).Decode(&uClaims); err == nil {
					if claims.Subject == "" {
						claims.Subject = uClaims.Subject
					}
					if claims.Email == "" {
						claims.Email = uClaims.Email
					}
					if claims.Name == "" {
						claims.Name = uClaims.Name
					}
					if claims.Username == "" {
						claims.Username = uClaims.Username
					}
				}
			}
		}
	}

	if claims.Subject == "" {
		return nil, errors.New("no subject claim found in ID token or userinfo")
	}

	if claims.Username == "" {
		if claims.Email != "" {
			claims.Username = strings.Split(claims.Email, "@")[0]
		} else {
			claims.Username = claims.Subject
		}
	}

	return &claims, nil
}

// StateCookie generates an encrypted or hex-encoded state parameter.
func GenerateState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
