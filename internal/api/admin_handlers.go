package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"kybookmarks-server/internal/crypto"
	"kybookmarks-server/internal/sso"
	"kybookmarks-server/internal/store"
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
	hash, err := crypto.HashPassword(req.Password, salt)
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

	_, _ = s.audit.Log("admin.user_created", admin.ID, "", clientIP(r), "admin created user: "+user.Username)
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
		hash, _ := crypto.HashPassword(req.Password, salt)
		user.PasswordHash = hash
		user.AuthSalt = salt
	}

	if err := s.store.UpdateAccount(user); err != nil {
		http.Error(w, "failed to update user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log("admin.user_updated", admin.ID, "", clientIP(r), "admin updated user: "+user.Username)
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

	_, _ = s.audit.Log("admin.user_deleted", admin.ID, "", clientIP(r), "admin deleted user: "+id)
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

	_, _ = s.audit.Log("admin.sso_updated", admin.ID, "", clientIP(r), "admin updated SSO configuration")
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
func (s *Server) handleDirectorySyncEvent(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Verify HMAC signature
	sigHeader := r.Header.Get("X-KySignOn-Signature")
	if s.cfg.SyncSecret != "" && sigHeader != "" {
		mac := hmac.New(sha256.New, []byte(s.cfg.SyncSecret))
		mac.Write(body)
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(sigHeader), []byte(expectedSig)) {
			http.Error(w, `{"error":"invalid_signature"}`, http.StatusUnauthorized)
			return
		}
	}

	var event struct {
		Action string `json:"action"` // "user.create", "user.update", "user.delete"
		User   struct {
			ID          string `json:"id"`
			Username    string `json:"username"`
			Email       string `json:"email"`
			DisplayName string `json:"displayName"`
			Role        string `json:"role"`
			Status      string `json:"status"`
		} `json:"user"`
	}

	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	switch event.Action {
	case "user.create", "user.provision":
		existing, _ := s.store.GetAccountByUsernameOrEmail(event.User.Username)
		if existing == nil {
			salt, _ := crypto.GenerateRandomHex(16)
			rndPass, _ := crypto.GenerateRandomHex(24)
			hash, _ := crypto.HashPassword(rndPass, salt)
			role := "user"
			if event.User.Role == "admin" {
				role = "admin"
			}
			newUser := &store.Account{
				Username:      event.User.Username,
				Email:         event.User.Email,
				DisplayName:   event.User.DisplayName,
				PasswordHash:  hash,
				AuthSalt:      salt,
				KDFIterations: 600000,
				Role:          role,
				Status:        "active",
				SSOSubject:    event.User.ID,
			}
			_ = s.store.CreateAccount(newUser)
			_, _ = s.audit.Log("sync.user_created", newUser.ID, "", clientIP(r), "replicated user from KySignOn: "+newUser.Username)
		}
	case "user.update":
		existing, _ := s.store.GetAccountByUsernameOrEmail(event.User.Username)
		if existing != nil {
			if event.User.DisplayName != "" {
				existing.DisplayName = event.User.DisplayName
			}
			if event.User.Email != "" {
				existing.Email = event.User.Email
			}
			if event.User.Role != "" {
				existing.Role = event.User.Role
			}
			if event.User.Status != "" {
				existing.Status = event.User.Status
			}
			_ = s.store.UpdateAccount(existing)
			_, _ = s.audit.Log("sync.user_updated", existing.ID, "", clientIP(r), "synced user update from KySignOn: "+existing.Username)
		}
	case "user.delete":
		existing, _ := s.store.GetAccountByUsernameOrEmail(event.User.Username)
		if existing != nil {
			_ = s.store.DeleteAccount(existing.ID)
			_, _ = s.audit.Log("sync.user_deleted", existing.ID, "", clientIP(r), "synced user deletion from KySignOn: "+existing.Username)
		}
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
