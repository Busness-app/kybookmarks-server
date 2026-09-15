package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"time"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

// ssoLogoutBodyLimit bounds a logout delivery; a logout token is a few hundred bytes.
const ssoLogoutBodyLimit = 64 << 10

// handleSSOLogout receives an OIDC back-channel logout from the issuer. The token alone
// authorises the request: no cookie, no CSRF, and nothing about the caller's address is
// trusted. A verified token that matches no session is still a success so the issuer
// stops retrying; a replayed jti is refused so a captured delivery cannot be reused
// after a later login.
func (s *Server) handleSSOLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	reject := func(status int, code string) { writeJSON(w, status, map[string]string{"error": code}) }

	// Outstanding logouts stay valid after an admin disables SSO: revocation is the
	// safe direction. Only the issuer and client identity must still be known.
	settings := s.ssoStore.Load()
	if settings.IssuerURL == "" || settings.ClientID == "" {
		reject(http.StatusBadRequest, "invalid_logout")
		return
	}

	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		reject(http.StatusBadRequest, "invalid_logout")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, ssoLogoutBodyLimit)
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			reject(http.StatusRequestEntityTooLarge, "invalid_logout")
			return
		}
		reject(http.StatusBadRequest, "invalid_logout")
		return
	}
	tokens := r.PostForm["logout_token"] // the body only; a token in the query string does not count
	if len(tokens) != 1 || tokens[0] == "" {
		reject(http.StatusBadRequest, "invalid_logout")
		return
	}

	// A caller that disconnects mid-fetch must not leave the JWKS cache half-refreshed
	// for the next delivery, so verification runs on its own bounded budget.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
	defer cancel()
	// An unverified token is anyone's; like a bad sync signature it goes to the process
	// log, not the audit chain, so a stranger cannot grow the chain at will.
	claims, err := s.verifierFor(settings).VerifyLogout(ctx, tokens[0])
	if err != nil {
		log.Printf("sso: rejected logout from %s: %v", clientIP(r), err)
		reject(http.StatusBadRequest, "invalid_logout")
		return
	}

	// The record must outlive a callback that started before this logout arrived: the
	// login transaction cookie lasts five minutes, so a fence shorter than that could
	// expire before the pending callback tries to mint its session.
	retain := time.Now().Add(5 * time.Minute)
	if claims.ReplayUntil.After(retain) {
		retain = claims.ReplayUntil
	}
	revoked, err := s.store.ApplySSOLogout(store.SSOLogoutEvent{
		Issuer:   settings.IssuerURL,
		ClientID: settings.ClientID,
		JTI:      claims.JWTID,
		Subject:  claims.Subject,
		SID:      claims.SessionID,
		IssuedAt: claims.IssuedAt.Unix(),
	}, retain)
	if errors.Is(err, store.ErrAlreadyExists) {
		s.auditEvent(r, "sso.logout_rejected", "", "", "replayed logout token jti="+claims.JWTID)
		reject(http.StatusBadRequest, "invalid_logout")
		return
	}
	if err != nil {
		reject(http.StatusInternalServerError, "logout_failed")
		return
	}
	s.auditEvent(r, "auth.sso_logout", "", "", fmt.Sprintf("jti=%s sessions=%d", claims.JWTID, revoked))
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}
