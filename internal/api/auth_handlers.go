package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Busness-app/kybookmarks-server/internal/crypto"
	"github.com/Busness-app/kybookmarks-server/internal/sso"
	"github.com/Busness-app/kybookmarks-server/internal/store"
)

type LoginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	AuthSecret string `json:"authSecret,omitempty"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ip := clientIP(r)
	cleanUser := strings.ToLower(strings.TrimSpace(req.Username))

	// Check rate limit / 3-attempt 15-minute block
	s.loginAttemptsMu.Lock()
	tracker, exists := s.loginAttempts[cleanUser]
	if exists && time.Now().Before(tracker.blockedUntil) {
		s.loginAttemptsMu.Unlock()
		_, _ = s.audit.Log("auth.login_blocked", "", "", ip, "login blocked due to rate limit for "+cleanUser)
		http.Error(w, `{"error":"too_many_attempts","message":"Account temporarily locked for 15 minutes"}`, http.StatusTooManyRequests)
		return
	}
	s.loginAttemptsMu.Unlock()

	acc, err := s.store.GetAccountByUsernameOrEmail(cleanUser)
	if err != nil {
		s.recordFailedLogin(cleanUser)
		_, _ = s.audit.Log("auth.login_failed", "", "", ip, "user not found: "+cleanUser)
		http.Error(w, `{"error":"invalid_credentials"}`, http.StatusUnauthorized)
		return
	}

	if acc.Status != "active" {
		http.Error(w, `{"error":"account_suspended"}`, http.StatusForbidden)
		return
	}

	// Verify credentials (support authSecret or raw password fallback)
	secret := req.AuthSecret
	verified := false
	if secret != "" {
		verified = crypto.VerifyPassword(secret, acc.AuthSalt, acc.PasswordHash)
	}
	if !verified && req.Password != "" {
		verified = crypto.VerifyPassword(req.Password, acc.AuthSalt, acc.PasswordHash)
	}

	if !verified {
		s.recordFailedLogin(cleanUser)
		_, _ = s.audit.Log("auth.login_failed", acc.ID, "", ip, "bad password for "+cleanUser)
		http.Error(w, `{"error":"invalid_credentials"}`, http.StatusUnauthorized)
		return
	}

	// Reset failed attempts on success
	s.loginAttemptsMu.Lock()
	delete(s.loginAttempts, cleanUser)
	s.loginAttemptsMu.Unlock()

	token, err := s.startSession(w, r, acc.ID, "")
	if err != nil {
		http.Error(w, "failed to start session", http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("auth.login", acc.ID, "", ip, "user signed in")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": token,
		"user":  acc,
	})
}

func (s *Server) recordFailedLogin(user string) {
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()

	tracker, exists := s.loginAttempts[user]
	if !exists {
		tracker = &loginAttemptTracker{}
		s.loginAttempts[user] = tracker
	}
	tracker.count++
	if tracker.count >= 3 {
		tracker.blockedUntil = time.Now().Add(15 * time.Minute)
		tracker.count = 0
	}
}

func (s *Server) handlePaperRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username       string `json:"username"`
		RecoverySecret string `json:"recoverySecret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ip := clientIP(r)
	cleanUser := strings.ToLower(strings.TrimSpace(req.Username))

	// Recovery mints a session and returns the vault key wrappers, so it gets the
	// same lockout as login. Without it this is an unmetered scrypt oracle.
	s.loginAttemptsMu.Lock()
	tracker, exists := s.loginAttempts[cleanUser]
	if exists && time.Now().Before(tracker.blockedUntil) {
		s.loginAttemptsMu.Unlock()
		_, _ = s.audit.Log("auth.recovery_blocked", "", "", ip, "recovery blocked due to rate limit for "+cleanUser)
		http.Error(w, `{"error":"too_many_attempts","message":"Account temporarily locked for 15 minutes"}`, http.StatusTooManyRequests)
		return
	}
	s.loginAttemptsMu.Unlock()

	acc, err := s.store.GetAccountByUsernameOrEmail(cleanUser)
	if err != nil {
		s.recordFailedLogin(cleanUser)
		_, _ = s.audit.Log("auth.recovery_failed", "", "", ip, "recovery attempt for unknown user: "+cleanUser)
		http.Error(w, `{"error":"invalid_recovery_key"}`, http.StatusUnauthorized)
		return
	}

	// Suspension must hold here exactly as it does on the login path.
	if acc.Status != "active" {
		_, _ = s.audit.Log("auth.recovery_failed", acc.ID, "", ip, "recovery attempt on suspended account")
		http.Error(w, `{"error":"account_suspended"}`, http.StatusForbidden)
		return
	}

	cleanSecret := strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(req.RecoverySecret)), "-", "")
	if acc.RecoveryVerifier == "" || !crypto.VerifyPassword(cleanSecret, acc.AuthSalt, acc.RecoveryVerifier) {
		s.recordFailedLogin(cleanUser)
		_, _ = s.audit.Log("auth.recovery_failed", acc.ID, "", ip, "failed recovery key attempt")
		http.Error(w, `{"error":"invalid_recovery_key"}`, http.StatusUnauthorized)
		return
	}

	s.loginAttemptsMu.Lock()
	delete(s.loginAttempts, cleanUser)
	s.loginAttemptsMu.Unlock()

	token, err := s.startSession(w, r, acc.ID, "")
	if err != nil {
		http.Error(w, "failed to start session", http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("auth.recovery_success", acc.ID, "", clientIP(r), "user unlocked vault via paper recovery key")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": token,
		"user":  acc,
	})
}

func (s *Server) handleLoginParams(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	acc, err := s.store.GetAccountByUsernameOrEmail(username)
	if err != nil {
		// Unknown users get a salt derived from the username under a server-held
		// key: stable across requests, indistinguishable from a real random salt.
		// A published constant here would announce which usernames exist.
		mac := hmac.New(sha256.New, s.saltKey)
		mac.Write([]byte(strings.ToLower(username)))
		writeJSON(w, http.StatusOK, map[string]any{
			"salt":       hex.EncodeToString(mac.Sum(nil)[:16]),
			"iterations": 600000,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"salt":       acc.AuthSalt,
		"iterations": acc.KDFIterations,
	})
}

func (s *Server) handleSetupCheck(w http.ResponseWriter, r *http.Request) {
	count, err := s.store.CountAccounts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"needsSetup": count == 0,
	})
}

func (s *Server) handleSetupInit(w http.ResponseWriter, r *http.Request) {
	count, err := s.store.CountAccounts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, `{"error":"already_configured","message":"Server is already initialized"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Username         string `json:"username"`
		Email            string `json:"email"`
		DisplayName      string `json:"displayName"`
		Password         string `json:"password"`
		AuthSecret       string `json:"authSecret"`
		AuthSalt         string `json:"authSalt"`
		KDFIterations    int    `json:"kdfIterations"`
		PasswordKeyWrap  string `json:"passwordKeyWrap"`
		RecoveryKeyWrap  string `json:"recoveryKeyWrap"`
		RecoveryVerifier string `json:"recoveryVerifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Username) < 3 || len(req.Password) < 12 {
		http.Error(w, "username must be >= 3 chars and password >= 12 chars", http.StatusBadRequest)
		return
	}

	salt := req.AuthSalt
	if salt == "" {
		salt, _ = crypto.GenerateRandomHex(16)
	}

	secretToHash := req.AuthSecret
	if secretToHash == "" {
		secretToHash = req.Password
	}
	hash, err := crypto.HashPassword(secretToHash, salt)
	if err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	admin := &store.Account{
		Username:         req.Username,
		Email:            req.Email,
		DisplayName:      req.DisplayName,
		PasswordHash:     hash,
		AuthSalt:         salt,
		KDFIterations:    req.KDFIterations,
		Role:             "admin",
		Status:           "active",
		PasswordKeyWrap:  req.PasswordKeyWrap,
		RecoveryKeyWrap:  req.RecoveryKeyWrap,
		RecoveryVerifier: req.RecoveryVerifier,
	}

	// Re-check the account count inside the insert. Hashing above is deliberately
	// slow, which is a wide enough window for a second request to pass the check
	// at the top of this handler and enrol a second admin.
	if err := s.store.CreateFirstAdmin(admin); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			http.Error(w, `{"error":"already_configured","message":"Server is already initialized"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, "failed to create admin: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("setup.init", admin.ID, "", clientIP(r), "initialized initial admin account: "+admin.Username)
	token, _ := s.startSession(w, r, admin.ID, "")

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": token,
		"user":  admin,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	acc, ok := s.currentUser(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, acc)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		_ = s.store.DeleteSession(hashToken(cookie.Value))
	}

	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)

	var req struct {
		OldPassword     string `json:"oldPassword"`
		NewPassword     string `json:"newPassword"`
		NewAuthSecret   string `json:"newAuthSecret"`
		NewAuthSalt     string `json:"newAuthSalt"`
		PasswordKeyWrap string `json:"passwordKeyWrap"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.NewPassword) < 12 {
		http.Error(w, "new password must be at least 12 characters", http.StatusBadRequest)
		return
	}

	if !crypto.VerifyPassword(req.OldPassword, acc.AuthSalt, acc.PasswordHash) {
		http.Error(w, `{"error":"invalid_old_password"}`, http.StatusUnauthorized)
		return
	}

	salt := req.NewAuthSalt
	if salt == "" {
		salt, _ = crypto.GenerateRandomHex(16)
	}
	secretToHash := req.NewAuthSecret
	if secretToHash == "" {
		secretToHash = req.NewPassword
	}
	newHash, err := crypto.HashPassword(secretToHash, salt)
	if err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	acc.PasswordHash = newHash
	acc.AuthSalt = salt
	acc.PasswordKeyWrap = req.PasswordKeyWrap

	if err := s.store.UpdateAccount(acc); err != nil {
		http.Error(w, "failed to update password", http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("auth.password_change", acc.ID, "", clientIP(r), "password updated and key re-wrapped")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleUpdateKeyWraps(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)

	var req struct {
		PasswordKeyWrap  string `json:"passwordKeyWrap"`
		RecoveryKeyWrap  string `json:"recoveryKeyWrap"`
		RecoveryVerifier string `json:"recoveryVerifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.PasswordKeyWrap != "" {
		acc.PasswordKeyWrap = req.PasswordKeyWrap
	}
	if req.RecoveryKeyWrap != "" {
		acc.RecoveryKeyWrap = req.RecoveryKeyWrap
	}
	if req.RecoveryVerifier != "" {
		acc.RecoveryVerifier = req.RecoveryVerifier
	}

	if err := s.store.UpdateAccount(acc); err != nil {
		http.Error(w, "failed to update key envelopes", http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("vault.key_wraps_updated", acc.ID, "", clientIP(r), "updated vault key wrappers")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSSOConfig(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":   settings.Enabled,
		"issuerUrl": settings.IssuerURL,
		"clientId":  settings.ClientID,
	})
}

func (s *Server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	if !settings.Enabled || settings.IssuerURL == "" || settings.ClientID == "" {
		http.Error(w, "SSO is not configured or disabled", http.StatusServiceUnavailable)
		return
	}

	linkUserID := ""
	if r.URL.Query().Get("link") == "true" {
		if auth, ok := s.currentUser(r); ok {
			linkUserID = auth.ID
		}
	}

	verifier, challenge, err := sso.GeneratePKCE()
	if err != nil {
		http.Error(w, "failed to generate PKCE challenge", http.StatusInternalServerError)
		return
	}

	stateBytes := make([]byte, 16)
	_, _ = rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	cookieVal := fmt.Sprintf("%s|%s|%s", state, verifier, linkUserID)
	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     ssoCookieName,
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	disc, err := sso.DiscoverEndpoints(r.Context(), settings.IssuerURL)
	if err != nil {
		http.Error(w, "failed to discover OIDC endpoints: "+err.Error(), http.StatusBadGateway)
		return
	}

	scheme := "http"
	if secure {
		scheme = "https"
	}
	redirectURI := settings.RedirectURI
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("%s://%s/api/auth/oidc/callback", scheme, requestHost(r))
	}

	authURL, err := url.Parse(disc.AuthorizationEndpoint)
	if err != nil {
		http.Error(w, "invalid authorization endpoint", http.StatusInternalServerError)
		return
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", settings.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	if !settings.Enabled || settings.IssuerURL == "" {
		http.Error(w, "SSO is not configured or disabled", http.StatusServiceUnavailable)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(ssoCookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "missing or expired SSO cookie", http.StatusBadRequest)
		return
	}

	parts := strings.Split(cookie.Value, "|")
	if len(parts) < 2 || subtle.ConstantTimeCompare([]byte(parts[0]), []byte(state)) != 1 {
		http.Error(w, "invalid SSO state parameter", http.StatusBadRequest)
		return
	}
	codeVerifier := parts[1]
	linkUserID := ""
	if len(parts) >= 3 {
		linkUserID = parts[2]
	}

	disc, err := sso.DiscoverEndpoints(r.Context(), settings.IssuerURL)
	if err != nil {
		http.Error(w, "failed to discover OIDC endpoints: "+err.Error(), http.StatusBadGateway)
		return
	}

	scheme := "http"
	if isRequestSecure(r) {
		scheme = "https"
	}
	redirectURI := settings.RedirectURI
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("%s://%s/api/auth/oidc/callback", scheme, requestHost(r))
	}

	tok, err := sso.ExchangeCode(r.Context(), disc.TokenEndpoint, settings.ClientID, settings.ClientSecret, code, redirectURI, codeVerifier)
	if err != nil {
		http.Error(w, "failed to exchange token: "+err.Error(), http.StatusBadGateway)
		return
	}

	claims, err := sso.ParseClaims(r.Context(), tok.IDToken, tok.AccessToken, disc.UserinfoEndpoint)
	if err != nil {
		http.Error(w, "failed to parse claims: "+err.Error(), http.StatusBadGateway)
		return
	}
	// The subject is the only stable identifier we bind accounts to.
	if claims.Subject == "" {
		http.Error(w, "identity provider returned no subject claim", http.StatusBadGateway)
		return
	}

	var user *store.Account
	if linkUserID != "" {
		user, err = s.store.GetAccountByID(linkUserID)
		if err == nil {
			user.SSOSubject = claims.Subject
			_ = s.store.UpdateAccount(user)
			_, _ = s.audit.Log("sso.link", user.ID, "", clientIP(r), "linked account to SSO sub: "+claims.Subject)
		}
	}

	if user == nil {
		user, _ = s.store.GetAccountBySSOSubject(claims.Subject)
	}

	// Adopting an existing local account on first sign-in is a takeover primitive:
	// whoever controls the claim controls the account. Only a verified email is
	// trusted for that, never preferred_username, which most IdPs let users set.
	if user == nil && claims.EmailVerified && claims.Email != "" {
		if existing, lookupErr := s.store.GetAccountByUsernameOrEmail(claims.Email); lookupErr == nil {
			existing.SSOSubject = claims.Subject
			if err := s.store.UpdateAccount(existing); err != nil {
				http.Error(w, "failed to link SSO identity", http.StatusInternalServerError)
				return
			}
			_, _ = s.audit.Log("sso.link", existing.ID, "", clientIP(r), "adopted account via verified SSO email: "+claims.Email)
			user = existing
		}
	}

	if user == nil {
		if !settings.AutoProvision {
			http.Error(w, "Account does not exist and auto-provisioning is disabled", http.StatusForbidden)
			return
		}
		salt, _ := crypto.GenerateRandomHex(16)
		rndPass, _ := crypto.GenerateRandomHex(24)
		pHash, _ := crypto.HashPassword(rndPass, salt)
		role := "user"
		if claims.Role == "admin" {
			role = "admin"
		}
		newUser := &store.Account{
			Username:      claims.Username,
			Email:         claims.Email,
			DisplayName:   claims.Name,
			PasswordHash:  pHash,
			AuthSalt:      salt,
			KDFIterations: 600000,
			Role:          role,
			Status:        "active",
			SSOSubject:    claims.Subject,
		}
		if err := s.store.CreateAccount(newUser); err != nil {
			http.Error(w, "failed to provision user: "+err.Error(), http.StatusInternalServerError)
			return
		}
		user = newUser
		_, _ = s.audit.Log("sso.provision", user.ID, "", clientIP(r), "provisioned user from SSO: "+user.Username)
	}

	if user.Status != "active" {
		http.Error(w, "account is suspended", http.StatusForbidden)
		return
	}

	_, _ = s.startSession(w, r, user.ID, "")
	_, _ = s.audit.Log("auth.sso_login", user.ID, "", clientIP(r), "user signed in via SSO")

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleSSOUnlink(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)
	acc.SSOSubject = ""
	_ = s.store.UpdateAccount(acc)
	_, _ = s.audit.Log("sso.unlink", acc.ID, "", clientIP(r), "unlinked SSO identity")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "kybookmarks-server",
		"time":    time.Now().UTC(),
	})
}
