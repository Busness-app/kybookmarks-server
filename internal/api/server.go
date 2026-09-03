package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Busness-app/kybookmarks-server/internal/audit"
	"github.com/Busness-app/kybookmarks-server/internal/crypto"
	"github.com/Busness-app/kybookmarks-server/internal/devices"
	"github.com/Busness-app/kybookmarks-server/internal/sso"
	"github.com/Busness-app/kybookmarks-server/internal/store"
	"github.com/Busness-app/kybookmarks-server/internal/vault"
)

const (
	sessionCookieName = "kybookmark_session"
	csrfCookieName    = "csrf_token"
	ssoCookieName     = "kybookmark_sso_state"
)

type Config struct {
	WebDir     string
	DataDir    string
	ConfigDir  string
	SyncSecret string
}

type Server struct {
	store    *store.Store
	vault    *vault.Manager
	devices  *devices.Store
	ssoStore *sso.Store
	audit    *audit.Logger
	cfg      Config

	loginAttemptsMu sync.Mutex
	loginAttempts   map[string]*loginAttemptTracker

	// saltKey derives the decoy login salt served for unknown usernames.
	saltKey []byte

	// auditFailures counts audit writes that did not land. /api/health reports only
	// whether it is non-zero; the count itself stays out of an unauthenticated body.
	auditFailures atomic.Uint64
}

// auditEvent records an event on the tamper-evident chain, and refuses to let a failure
// of that write be silent.
//
// It does not fail the request, and that is a judgement call rather than an oversight.
// Every call site logs *after* the thing has already happened: the user is deleted, the
// session is issued, the password is rejected. A 500 at that point would neither undo the
// action nor restore the record, and it would invite a retry that repeats it. What was
// wrong before was not the status code, it was that 28 call sites wrote `_, _ =` and a
// full or read-only audit volume erased admin.user_deleted, devices.paired and every
// auth.login_failed with nothing reaching the operator at all -- the same suppression
// Log's context handling exists to prevent, reached through the filesystem.
//
// So the failure gets two channels an operator already watches: stderr, where LOGGING.md
// sends security events, and /api/health, which turns "degraded" and says no more than
// that. Health stays HTTP 200 while degraded on purpose: nothing here sheds a 503 from
// rotation, so it would only tell the healthcheck and the uptime poller that a full disk
// is an outage, and a restart empties no disk. TestAuditWriteFailureIsNotSilent covers
// both channels; TestDegradedHealthStaysHTTP200 pins the status code.
//
// Details are not logged: they carry usernames, and LOGGING.md keeps application logs to
// coarse actor identifiers. The chain is where the detail belongs.
func (s *Server) auditEvent(r *http.Request, action, userID, deviceID, details string) {
	if _, err := s.audit.Log(r.Context(), action, userID, deviceID, clientIP(r), details); err != nil {
		s.auditFailures.Add(1)
		log.Printf("audit: %s for user %q was NOT recorded: %v", action, userID, err)
	}
}

// loadOrCreateSaltKey keeps the decoy salt stable across restarts, so an
// attacker cannot spot unknown usernames by watching their salt change.
func loadOrCreateSaltKey(configDir string) []byte {
	path := filepath.Join(configDir, "enum.key")
	if raw, err := os.ReadFile(path); err == nil {
		if key, err := hex.DecodeString(strings.TrimSpace(string(raw))); err == nil && len(key) >= 32 {
			return key
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// Without randomness we cannot serve a decoy salt safely; a fresh random
		// key each restart is still better than a published constant.
		panic("kybookmarks: no entropy available: " + err.Error())
	}
	if configDir != "" {
		if err := os.MkdirAll(configDir, 0o700); err == nil {
			_ = os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600)
		}
	}
	return key
}

type loginAttemptTracker struct {
	count        int
	blockedUntil time.Time
}

func NewServer(s *store.Store, vm *vault.Manager, ds *devices.Store, ss *sso.Store, al *audit.Logger, cfg Config) *Server {
	return &Server{
		store:         s,
		vault:         vm,
		devices:       ds,
		ssoStore:      ss,
		audit:         al,
		cfg:           cfg,
		loginAttempts: make(map[string]*loginAttemptTracker),
		saltKey:       loadOrCreateSaltKey(cfg.ConfigDir),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public Auth & Setup
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/recovery", s.handlePaperRecovery)
	mux.HandleFunc("GET /api/auth/login-params", s.handleLoginParams)
	mux.HandleFunc("GET /api/auth/sso-config", s.handleSSOConfig)
	mux.HandleFunc("GET /api/auth/oidc/login", s.handleSSOLogin)
	mux.HandleFunc("GET /auth/oidc/login", s.handleSSOLogin)
	mux.HandleFunc("GET /auth/sso/login", s.handleSSOLogin)
	mux.HandleFunc("GET /api/auth/oidc/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /auth/oidc/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /auth/sso/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/setup", s.handleSetupCheck)
	mux.HandleFunc("POST /api/setup", s.handleSetupInit)

	// Explicit Favicon routes
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		if data, err := os.ReadFile(filepath.Join(s.cfg.WebDir, "favicon.svg")); err == nil {
			_, _ = w.Write(data)
			return
		}
		_, _ = w.Write([]byte(defaultFaviconSVG))
	})
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		if data, err := os.ReadFile(filepath.Join(s.cfg.WebDir, "favicon.ico")); err == nil {
			_, _ = w.Write(data)
			return
		}
		_, _ = w.Write([]byte(defaultFaviconSVG))
	})

	// Self & Session
	mux.HandleFunc("GET /api/auth/me", s.withAuth(s.handleMe))
	mux.HandleFunc("POST /api/auth/logout", s.withAuth(s.handleLogout))
	mux.HandleFunc("POST /api/auth/password", s.withAuth(s.handleChangePassword))
	mux.HandleFunc("POST /api/auth/key-wraps", s.withAuth(s.handleUpdateKeyWraps))
	mux.HandleFunc("POST /api/settings/sso/unlink", s.withAuth(s.handleSSOUnlink))

	// Vault Sync & History
	mux.HandleFunc("POST /api/vault/sync", s.withAuth(s.handleVaultSync))
	mux.HandleFunc("GET /api/vault/objects", s.withAuth(s.handleGetVaultObjects))
	mux.HandleFunc("GET /api/vault/history", s.withAuth(s.handleGetHistory))

	// Device Pairing (Public & Authenticated)
	mux.HandleFunc("POST /api/devices/pair/request", s.withAuth(s.handlePairRequest))
	mux.HandleFunc("POST /api/devices/pair/redeem", s.handlePairRedeem)
	mux.HandleFunc("POST /api/devices/pair/approve", s.withAuth(s.handlePairApprove))
	mux.HandleFunc("GET /api/devices", s.withAuth(s.handleListDevices))
	mux.HandleFunc("DELETE /api/devices/{id}", s.withAuth(s.handleRevokeDevice))

	// Admin API
	mux.HandleFunc("GET /api/admin/users", s.withAdmin(s.handleAdminListUsers))
	mux.HandleFunc("POST /api/admin/users", s.withAdmin(s.handleAdminCreateUser))
	mux.HandleFunc("PUT /api/admin/users/{id}", s.withAdmin(s.handleAdminUpdateUser))
	mux.HandleFunc("DELETE /api/admin/users/{id}", s.withAdmin(s.handleAdminDeleteUser))
	mux.HandleFunc("GET /api/admin/sso", s.withAdmin(s.handleAdminGetSSO))
	mux.HandleFunc("POST /api/admin/sso", s.withAdmin(s.handleAdminSaveSSO))
	mux.HandleFunc("GET /api/admin/audit", s.withAdmin(s.handleAdminAudit))
	mux.HandleFunc("POST /api/admin/audit/verify", s.withAdmin(s.handleAdminAuditVerify))

	// Suite Sync Webhook (Signed by KySignOn)
	mux.HandleFunc("POST /api/sync/events", s.handleDirectorySyncEvent)

	// SPA Static File Serving
	if s.cfg.WebDir != "" {
		mux.Handle("/", s.spaHandler())
	}

	return s.securityHeaders(mux)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:;")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) spaHandler() http.Handler {
	fs := http.FileServer(http.Dir(s.cfg.WebDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		path := filepath.Join(s.cfg.WebDir, filepath.Clean(r.URL.Path))
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}

		// Fallback to index.html for client-side routing
		http.ServeFile(w, r, filepath.Join(s.cfg.WebDir, "index.html"))
	})
}

type contextKey string

const userContextKey = contextKey("user")

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, sess, ok := s.currentSession(r)
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		// CSRF protection for state-changing browser requests
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			if !s.validateCSRF(r, sess) {
				http.Error(w, `{"error":"invalid_csrf_token"}`, http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	}
}

func (s *Server) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, sess, ok := s.currentSession(r)
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if user.Role != "admin" {
			http.Error(w, `{"error":"forbidden","message":"admin role required"}`, http.StatusForbidden)
			return
		}

		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			if !s.validateCSRF(r, sess) {
				http.Error(w, `{"error":"invalid_csrf_token"}`, http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	}
}

func (s *Server) currentUser(r *http.Request) (*store.Account, bool) {
	acc, _, ok := s.currentSession(r)
	return acc, ok
}

func (s *Server) currentSession(r *http.Request) (*store.Account, *store.Session, bool) {
	token := ""
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		token = cookie.Value
	} else if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
		token = strings.TrimPrefix(authHdr, "Bearer ")
	}

	if token == "" {
		return nil, nil, false
	}

	tokenHash := hashToken(token)
	sess, err := s.store.GetSession(tokenHash)
	if err != nil {
		return nil, nil, false
	}

	acc, err := s.store.GetAccountByID(sess.UserID)
	if err != nil || acc.Status != "active" {
		return nil, nil, false
	}

	return acc, sess, true
}

func (s *Server) validateCSRF(r *http.Request, sess *store.Session) bool {
	// Bearer tokens (used by native apps/extensions) are immune to CSRF
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return true
	}

	// Compare against the token minted with this session, not against the cookie
	// echoed back. Anything able to plant a csrf_token cookie -- a sibling
	// subdomain, say -- can satisfy a cookie-versus-header check on its own.
	if sess == nil || sess.CSRFToken == "" {
		return false
	}

	headerToken := r.Header.Get("X-CSRF-Token")
	return headerToken != "" && hmac.Equal([]byte(headerToken), []byte(sess.CSRFToken))
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID, deviceID string) (string, error) {
	rawToken, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", err
	}
	csrfToken, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	sess := &store.Session{
		TokenHash: hashToken(rawToken),
		UserID:    userID,
		DeviceID:  deviceID,
		CSRFToken: csrfToken,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}

	if err := s.store.CreateSession(sess); err != nil {
		return "", err
	}

	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    rawToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 30,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 30,
	})

	return rawToken, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func isRequestSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func requestHost(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	return r.Host
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

const defaultFaviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
  <rect width="64" height="64" rx="14" fill="#0d0f14"/>
  <rect x="1" y="1" width="62" height="62" rx="13" stroke="#4deeea" stroke-opacity="0.3" stroke-width="1.5"/>
  <path d="M20 12 H44 C45.1 12 46 12.9 46 14 V52 L32 42 L18 52 V14 C18 12.9 18.9 12 20 12 Z" fill="#121820" stroke="#4deeea" stroke-width="2.5" stroke-linejoin="round"/>
  <path d="M32 20 L34.5 25.5 L40.5 26.2 L36 30.2 L37.2 36 L32 33 L26.8 36 L28 30.2 L23.5 26.2 L29.5 25.5 Z" fill="#0d0f14" stroke="#4deeea" stroke-width="1.8" stroke-linejoin="round"/>
  <circle cx="32" cy="28" r="1.5" fill="#4deeea"/>
</svg>`
