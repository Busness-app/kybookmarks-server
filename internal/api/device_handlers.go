package api

import (
	"encoding/json"
	"net/http"

	"github.com/Busness-app/kybookmarks-server/internal/devices"
	"github.com/Busness-app/kybookmarks-server/internal/store"
)

func (s *Server) handlePairRequest(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)

	// The account is taken from the session, never from the body: the response
	// carries the PIN and pairing token, which enroll a device onto that account.
	var req struct {
		DeviceName string `json:"deviceName"`
		DeviceType string `json:"deviceType"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.DeviceName == "" {
		req.DeviceName = "KyBookmarks Client"
	}
	if req.DeviceType == "" {
		req.DeviceType = "browser_chrome"
	}

	sess, err := s.devices.RequestPairing(acc.ID, req.DeviceName, req.DeviceType)
	if err != nil {
		http.Error(w, "failed to request pairing: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, sess)
}

func (s *Server) handlePairApprove(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)

	var req struct {
		PIN              string `json:"pin"`
		VaultKeyEnvelope string `json:"vaultKeyEnvelope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.devices.ApprovePairing(acc.ID, req.PIN, req.VaultKeyEnvelope); err != nil {
		if err == devices.ErrInvalidPIN {
			http.Error(w, `{"error":"invalid_or_expired_pin"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log(r.Context(), "devices.pair_approved", acc.ID, "", clientIP(r), "approved device pairing PIN")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handlePairRedeem(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PairingToken string `json:"pairingToken"`
		PublicKey    string `json:"publicKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	sess, err := s.devices.RedeemPairing(req.PairingToken, req.PublicKey)
	if err != nil {
		if err == devices.ErrNotApproved {
			http.Error(w, `{"error":"waiting_approval"}`, http.StatusAccepted)
			return
		}
		if err == devices.ErrPairingExpired {
			http.Error(w, `{"error":"expired"}`, http.StatusGone)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Register device in store. A session must never outlive a failed enrolment,
	// so both steps fail closed.
	dev := &store.Device{
		UserID:      sess.UserID,
		DeviceName:  sess.DeviceName,
		DeviceType:  sess.DeviceType,
		PublicKey:   req.PublicKey,
		KeyEnvelope: sess.VaultKeyEnvelope,
	}
	if err := s.store.CreateDevice(dev); err != nil {
		http.Error(w, "failed to register device", http.StatusInternalServerError)
		return
	}

	// Create session for the newly paired device
	token, err := s.startSession(w, r, sess.UserID, dev.ID)
	if err != nil {
		http.Error(w, "failed to start session", http.StatusInternalServerError)
		return
	}
	_, _ = s.audit.Log(r.Context(), "devices.paired", sess.UserID, dev.ID, clientIP(r), "completed device pairing for: "+dev.DeviceName)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"token":            token,
		"deviceId":         dev.ID,
		"vaultKeyEnvelope": sess.VaultKeyEnvelope,
	})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)

	devs, err := s.store.ListDevices(acc.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"devices": devs,
	})
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)
	deviceID := r.PathValue("id")

	if err := s.store.RevokeDevice(acc.ID, deviceID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = s.audit.Log(r.Context(), "devices.revoked", acc.ID, deviceID, clientIP(r), "revoked trusted device")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
