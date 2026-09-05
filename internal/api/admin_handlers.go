package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/syncauth"

	"github.com/Busness-app/kybookmarks-server/internal/crypto"
	"github.com/Busness-app/kybookmarks-server/internal/sso"
	"github.com/Busness-app/kybookmarks-server/internal/store"
)

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListAccounts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users": users,
	})
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	admin, _ := s.currentUser(r)

	var req struct {
		Username    string `json:"username"`
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
		Password    string `json:"password"`
		Role        string `json:"role"`
		Status      string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Username) < 3 || len(req.Password) < 12 {
		http.Error(w, "username must be >= 3 chars and password >= 12 chars", http.StatusBadRequest)
		return
	}

	salt, _ := crypto.GenerateRandomHex(16)
	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	role := "user"
	if req.Role == "admin" {
		role = "admin"
	}
	status := "active"
	if req.Status == "suspended" {
		status = "suspended"
	}

	user := &store.Account{
		Username:      req.Username,
		Email:         req.Email,
		DisplayName:   req.DisplayName,
		PasswordHash:  hash,
		AuthSalt:      salt,
		KDFIterations: 600000,
		Role:          role,
		Status:        status,
	}

	if err := s.store.CreateAccount(user); err != nil {
		http.Error(w, "failed to create user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.auditEvent(r, "admin.user_created", admin.ID, "", "admin created user: "+user.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"user": user,
	})
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	admin, _ := s.currentUser(r)
	id := r.PathValue("id")

	user, err := s.store.GetAccountByID(id)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	var req struct {
		DisplayName string `json:"displayName"`
		Email       string `json:"email"`
		Role        string `json:"role"`
		Status      string `json:"status"`
		Password    string `json:"password,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	if req.Status != "" {
		user.Status = req.Status
	}
	if len(req.Password) >= 12 {
		salt, _ := crypto.GenerateRandomHex(16)
		hash, _ := crypto.HashPassword(req.Password)
		user.PasswordHash = hash
		user.AuthSalt = salt
	}

	if err := s.store.UpdateAccount(user); err != nil {
		http.Error(w, "failed to update user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.auditEvent(r, "admin.user_updated", admin.ID, "", "admin updated user: "+user.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"user": user,
	})
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	admin, _ := s.currentUser(r)
	id := r.PathValue("id")

	if id == admin.ID {
		http.Error(w, "cannot delete your own admin account", http.StatusBadRequest)
		return
	}

	if err := s.store.DeleteAccount(id); err != nil {
		http.Error(w, "failed to delete user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.auditEvent(r, "admin.user_deleted", admin.ID, "", "admin deleted user: "+id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAdminGetSSO(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleAdminSaveSSO(w http.ResponseWriter, r *http.Request) {
	admin, _ := s.currentUser(r)

	var settings sso.SSOSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.ssoStore.Save(settings); err != nil {
		http.Error(w, "failed to save SSO settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.auditEvent(r, "admin.sso_updated", admin.ID, "", "admin updated SSO configuration")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"settings": settings,
	})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	entries, err := s.audit.ReadEntries(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
	})
}

func (s *Server) handleAdminAuditVerify(w http.ResponseWriter, r *http.Request) {
	valid, count, err := s.audit.VerifyChain()
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid": valid,
		"count": count,
		"error": errMsg,
	})
}

// Directory Sync Webhook from KySignOn
type scimValue struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

func (s *Server) handleDirectorySyncEvent(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// The signature was verified by syncAuth before this ran; body is the bytes it signed.
	var user struct {
		ID          string      `json:"id"`
		Username    string      `json:"userName"`
		DisplayName string      `json:"displayName"`
		Emails      []scimValue `json:"emails"`
		Roles       []scimValue `json:"roles"`
		Active      bool        `json:"active"`
	}

	if err := json.Unmarshal(body, &user); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	ev, _ := syncauth.EventFromContext(r)
	if user.ID == "" || (ev.Type != "user.deleted" && user.Username == "") {
		s.auditEvent(r, "sync.rejected", "", "", "invalid "+recoveryclient.AuditSafe(ev.Type)+" SCIM user")
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	email := primarySCIMValue(user.Emails)
	role := primarySCIMValue(user.Roles)

	switch ev.Type {
	case "user.created":
		existing, _ := s.store.GetAccountByUsernameOrEmail(user.Username)
		if existing != nil {
			// KySignOn is the signed source of truth. Upgrades can already have a local
			// account with this username; bind it now so a later delete cannot be
			// acknowledged while leaving the legacy password account active.
			existing.SSOSubject = user.ID
			existing.Email = email
			existing.DisplayName = user.DisplayName
			existing.Role = map[bool]string{true: "admin", false: "user"}[role == "admin"]
			existing.Status = map[bool]string{true: "active", false: "disabled"}[user.Active]
			if err := s.store.UpdateAccount(existing); err != nil {
				http.Error(w, `{"error":"sync_failed"}`, http.StatusInternalServerError)
				return
			}
			s.auditEvent(r, "sync.user_bound", existing.ID, "", "bound existing user to KySignOn: "+existing.Username)
		} else {
			salt, _ := crypto.GenerateRandomHex(16)
			rndPass, _ := crypto.GenerateRandomHex(24)
			hash, _ := crypto.HashPassword(rndPass)
			accountRole := "user"
			if role == "admin" {
				accountRole = "admin"
			}
			newUser := &store.Account{
				Username:      user.Username,
				Email:         email,
				DisplayName:   user.DisplayName,
				PasswordHash:  hash,
				AuthSalt:      salt,
				KDFIterations: 600000,
				Role:          accountRole,
				Status:        map[bool]string{true: "active", false: "disabled"}[user.Active],
				SSOSubject:    user.ID,
			}
			if err := s.store.CreateAccount(newUser); err != nil {
				http.Error(w, `{"error":"sync_failed"}`, http.StatusInternalServerError)
				return
			}
			s.auditEvent(r, "sync.user_created", newUser.ID, "", "replicated user from KySignOn: "+newUser.Username)
		}
	case "user.updated":
		existing, _ := s.store.GetAccountByUsernameOrEmail(user.Username)
		if existing != nil {
			if user.DisplayName != "" {
				existing.DisplayName = user.DisplayName
			}
			if email != "" {
				existing.Email = email
			}
			if role != "" {
				existing.Role = role
			}
			existing.Status = map[bool]string{true: "active", false: "disabled"}[user.Active]
			if err := s.store.UpdateAccount(existing); err != nil {
				http.Error(w, `{"error":"sync_failed"}`, http.StatusInternalServerError)
				return
			}
			s.auditEvent(r, "sync.user_updated", existing.ID, "", "synced user update from KySignOn: "+existing.Username)
		}
	case "user.deleted":
		existing, _ := s.store.GetAccountBySSOSubject(user.ID)
		if existing != nil {
			if err := s.store.DeleteAccount(existing.ID); err != nil {
				http.Error(w, `{"error":"sync_failed"}`, http.StatusInternalServerError)
				return
			}
			s.auditEvent(r, "sync.user_deleted", existing.ID, "", "synced user deletion from KySignOn: "+existing.Username)
		}
	default:
		s.auditEvent(r, "sync.rejected", "", "", "unsupported signed event type "+recoveryclient.AuditSafe(ev.Type))
		http.Error(w, `{"error":"unsupported_event"}`, http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func primarySCIMValue(values []scimValue) string {
	for _, value := range values {
		if value.Primary {
			return value.Value
		}
	}
	if len(values) > 0 {
		return values[0].Value
	}
	return ""
}
