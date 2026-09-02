package api

import (
	"encoding/json"
	"net/http"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

func (s *Server) handleVaultSync(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)

	var req store.SyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid sync payload", http.StatusBadRequest)
		return
	}

	resp, err := s.vault.Sync(acc.ID, req)
	if err != nil {
		http.Error(w, "sync failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log(r.Context(), "vault.sync", acc.ID, "", clientIP(r), "processed sync batch")
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetVaultObjects(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)

	includeDeleted := r.URL.Query().Get("trash") == "true"
	objects, err := s.vault.GetObjects(acc.ID, includeDeleted)
	if err != nil {
		http.Error(w, "failed to get vault objects: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"objects": objects,
	})
}

func (s *Server) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)

	objectID := r.URL.Query().Get("objectId")
	if objectID == "" {
		http.Error(w, "objectId required", http.StatusBadRequest)
		return
	}

	history, err := s.vault.GetObjectHistory(acc.ID, objectID)
	if err != nil {
		http.Error(w, "failed to get object history: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"history": history,
	})
}
