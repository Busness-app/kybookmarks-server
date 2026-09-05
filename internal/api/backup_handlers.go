package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"

	"github.com/Busness-app/kybookmarks-server/internal/audit"
	"github.com/Busness-app/kybookmarks-server/internal/backup"
)

// recoveryClient is the slice of the KyRecovery client the handlers use; tests stand in a
// fake without reaching the network.
type recoveryClient interface {
	ClaimPairing(ctx context.Context, serverURL, pairingCode, serviceName, appName string) (recoveryclient.PairingResult, error)
	recoveryclient.Depositor
}

// depositBudget bounds a manual run: the lib's own upload budget is 15 minutes.
const depositBudget = 16 * time.Minute

func (s *Server) settings() recoveryclient.Settings { return backup.Settings(s.store) }

func (s *Server) collect(ctx context.Context) (recoveryclient.Payload, error) {
	return backup.Collect(ctx, s.store, s.cfg.DataDir, s.cfg.ConfigDir, s.cfg.AppVersion)
}

// auditBackup records one backup event with the lib's details flattened onto the line.
func (s *Server) auditBackup(r *http.Request, action, userID, outcome string, details map[string]any) {
	s.auditEvent(r, action, userID, "", backup.AuditDetails(details)+" outcome="+outcome)
}

// auditCritical is auditBackup for events that must not happen unrecorded: it reports
// whether the record landed. A mark that lagged is still a record.
func (s *Server) auditCritical(r *http.Request, action, userID, outcome string, details map[string]any) bool {
	_, err := s.audit.Log(r.Context(), action, userID, "", clientIP(r), backup.AuditDetails(details)+" outcome="+outcome)
	if err != nil && !errors.Is(err, audit.ErrMarkNotAdvanced) {
		s.auditFailures.Add(1)
		log.Printf("audit: %s was NOT recorded: %v", action, err)
		return false
	}
	return true
}

func backupError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func (s *Server) handleBackupDrill(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)
	payload, err := s.collect(r.Context())
	if err != nil {
		s.auditBackup(r, "admin.backup_drill", acc.ID, "failure", map[string]any{"error": err.Error()})
		backupError(w, http.StatusInternalServerError, "collect_failed", "Failed to collect the backup payload: "+recoveryclient.AuditSafe(err.Error()))
		return
	}
	root, err := backup.DrillRoot(s.cfg.DataDir)
	if err != nil {
		backupError(w, http.StatusInternalServerError, "drill_failed", err.Error())
		return
	}
	result, err := recoveryclient.Drill(r.Context(), root, payload, backup.Checks(payload))
	if err != nil {
		s.auditBackup(r, "admin.backup_drill", acc.ID, "failure", map[string]any{"error": err.Error()})
		backupError(w, http.StatusInternalServerError, "drill_failed", "Failed to run the restore drill")
		return
	}
	outcome := "success"
	if !result.Passed {
		outcome = "failure"
	}
	s.auditBackup(r, "admin.backup_drill", acc.ID, outcome, map[string]any{"passed": result.Passed, "duration_ms": result.DurationMs})
	writeJSON(w, http.StatusOK, result)
}

// handleExportCapsule hands the operator the capsule sealed to the suite recovery key. Only
// the custodians' shares open it. The export is refused rather than served unrecorded.
func (s *Server) handleExportCapsule(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)
	key, err := recoveryclient.LoadRecoveryKey(s.cfg.DataDir, s.settings())
	switch {
	case errors.Is(err, recoveryclient.ErrNotPaired):
		backupError(w, http.StatusPreconditionFailed, "no_recovery_key", "No recovery key; pair with KyRecovery or pin the suite key by hand")
		return
	case errors.Is(err, recoveryclient.ErrKeyMismatch):
		backupError(w, http.StatusConflict, "key_mismatch", "recovery.pub does not match the pinned key ID; refusing to seal")
		return
	case err != nil:
		backupError(w, http.StatusInternalServerError, "key_unreadable", "Failed to load the recovery key")
		return
	}
	payload, err := s.collect(r.Context())
	if err != nil {
		backupError(w, http.StatusInternalServerError, "collect_failed", "Failed to collect the backup payload: "+recoveryclient.AuditSafe(err.Error()))
		return
	}
	raw, m, err := recoveryclient.Seal(payload, key)
	if err != nil {
		if errors.Is(err, capsule.ErrCapsuleTooLarge) {
			backupError(w, http.StatusRequestEntityTooLarge, "too_large", recoveryclient.AuditSafe(err.Error()))
			return
		}
		backupError(w, http.StatusInternalServerError, "seal_failed", "Failed to seal the capsule")
		return
	}
	if !s.auditCritical(r, "admin.backup_exported", acc.ID, "success", map[string]any{
		"capsule_id": m.CapsuleID, "recovery_key_id": m.RecoveryKeyID, "size_bytes": len(raw),
	}) {
		backupError(w, http.StatusInternalServerError, "audit_failed", "The export could not be recorded on the audit chain, so it was refused")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.kycap"`, backup.AppName, recoveryclient.FilenameSafe(m.CapsuleID)))
	w.Header().Set("X-Recovery-Key-ID", m.RecoveryKeyID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// handlePairRemote claims a 6-digit PIN with KyRecovery, pins the suite recovery public key
// it hands back, and stores the URL and the sealed bearer token.
func (s *Server) handlePairRemote(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)
	var req struct {
		RecoveryURL string `json:"recovery_url"`
		PairingCode string `json:"pairing_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		backupError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON request body")
		return
	}
	if req.RecoveryURL == "" || req.PairingCode == "" {
		backupError(w, http.StatusBadRequest, "invalid_request", "Both recovery_url and pairing_code are required")
		return
	}
	if err := recoveryclient.ValidateURL(req.RecoveryURL, s.cfg.Backup.AllowPrivateRecovery); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "private") {
			msg += " (KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY=true admits a KyRecovery on your own network behind TLS)"
		}
		backupError(w, http.StatusBadRequest, "invalid_url", msg)
		return
	}
	target := recoveryclient.AuditSafe(req.RecoveryURL)
	fail := func(status int, code, msg string) {
		s.auditBackup(r, "admin.backup_paired", acc.ID, "failure", map[string]any{"recovery_url": target, "error": msg})
		backupError(w, status, code, msg)
	}
	result, err := s.recovery.ClaimPairing(r.Context(), req.RecoveryURL, req.PairingCode, backup.AppName, backup.AppName)
	if err != nil {
		fail(http.StatusBadRequest, "pairing_failed", recoveryclient.AuditSafe(err.Error()))
		return
	}
	if err := recoveryclient.StoreRecoveryKey(s.cfg.DataDir, s.settings(), result.Key); err != nil {
		if errors.Is(err, fs.ErrExist) {
			fail(http.StatusConflict, "key_conflict", "Already pinned to a different recovery key")
			return
		}
		fail(http.StatusInternalServerError, "pin_failed", "Failed to save the recovery key")
		return
	}
	if err := recoveryclient.StorePairing(s.settings(), s.sealer, req.RecoveryURL, result.APIToken); err != nil {
		s.auditBackup(r, "admin.backup_paired", acc.ID, "failure", map[string]any{
			"recovery_url": target, "recovery_key_id": result.Key.Public.ID(), "error": "key pinned but the pairing was not stored: " + err.Error(),
		})
		backupError(w, http.StatusInternalServerError, "pairing_failed", "Failed to persist the pairing")
		return
	}
	s.auditBackup(r, "admin.backup_paired", acc.ID, "success", map[string]any{
		"recovery_url": target, "recovery_key_id": result.Key.Public.ID(), "threshold": result.Key.Threshold,
		"total_shares": result.Key.TotalShares, "allow_private": s.cfg.Backup.AllowPrivateRecovery,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"paired": true, "recovery_url": req.RecoveryURL, "recovery_key_id": result.Key.Public.ID(),
		"threshold": result.Key.Threshold, "total_shares": result.Key.TotalShares,
	})
}

// handleRunBackup backs up now: one capsule to the local directory and, when paired, to
// KyRecovery. The run outlives the request so a closed tab cannot leave KyRecovery holding a
// capsule this instance has no receipt for.
func (s *Server) handleRunBackup(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(depositBudget))
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), depositBudget)
	defer cancel()
	rc := backup.RunConfig(s.cfg.DataDir, s.cfg.Backup.Dir, s.cfg.Backup.Keep, s.cfg.AppVersion, s.sealer)
	res, err := recoveryclient.Run(ctx, rc, s.settings(), func() (recoveryclient.Payload, error) { return s.collect(ctx) }, s.recovery)
	action, outcome, details := recoveryclient.Outcome(res, err)
	s.auditBackup(r, action, acc.ID, outcome, details)
	switch {
	case err == nil, errors.Is(err, recoveryclient.ErrReceiptUnrecorded):
		writeJSON(w, http.StatusOK, res)
	case errors.Is(err, recoveryclient.ErrNotPaired):
		backupError(w, http.StatusPreconditionFailed, "no_recovery_key", "No recovery key; pair with KyRecovery or pin the suite key by hand")
	case errors.Is(err, recoveryclient.ErrNoDestination):
		backupError(w, http.StatusPreconditionFailed, "no_destination", "Nowhere to put a capsule: pair with KyRecovery or set KYBOOKMARKS_BACKUP_DIR")
	case errors.Is(err, recoveryclient.ErrKeyPinMissing):
		backupError(w, http.StatusPreconditionFailed, "key_pin_missing", "Paired, but recovery.pub is missing or does not match the pin; restore it or re-pair")
	case errors.Is(err, recoveryclient.ErrInProgress):
		backupError(w, http.StatusConflict, "in_progress", "A backup is already in progress")
	case errors.Is(err, recoveryclient.ErrKeyMismatch):
		backupError(w, http.StatusConflict, "key_mismatch", "recovery.pub does not match the pinned key ID; refusing to seal")
	case errors.Is(err, capsule.ErrCapsuleTooLarge):
		backupError(w, http.StatusRequestEntityTooLarge, "too_large", recoveryclient.AuditSafe(err.Error()))
	case errors.Is(err, recoveryclient.ErrRemote):
		msg := "KyRecovery did not accept the deposit"
		if res.LocalPath != "" {
			msg += "; the local copy was written"
		}
		backupError(w, http.StatusBadGateway, "kyrecovery", msg)
	default:
		log.Printf("backup: run failed: %s", recoveryclient.AuditSafe(err.Error()))
		backupError(w, http.StatusInternalServerError, "backup_failed", "Backup failed before reaching KyRecovery")
	}
}

// handleUnpair forgets the KyRecovery URL and sealed token. The key pin, receipts and local
// copies stay; the credential dies only when the KyRecovery admin revokes it.
func (s *Server) handleUnpair(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)
	target, _ := s.store.GetSetting("kyrecovery_url")
	target = recoveryclient.AuditSafe(target)
	if err := recoveryclient.ClearPairing(s.settings()); err != nil {
		if errors.Is(err, recoveryclient.ErrNotPaired) {
			backupError(w, http.StatusPreconditionFailed, "not_paired", "Not paired with KyRecovery")
			return
		}
		s.auditBackup(r, "admin.backup_unpaired", acc.ID, "failure", map[string]any{"recovery_url": target, "error": err.Error()})
		backupError(w, http.StatusInternalServerError, "unpair_failed", "Failed to remove the pairing")
		return
	}
	s.auditBackup(r, "admin.backup_unpaired", acc.ID, "success", map[string]any{"recovery_url": target})
	writeJSON(w, http.StatusOK, map[string]any{"paired": false})
}

// handlePinKey pins the suite recovery public key by hand, for an instance with no KyRecovery.
// Write-once, like pairing.
func (s *Server) handlePinKey(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)
	var req struct {
		PublicKey   string `json:"public_key"`
		Threshold   int    `json:"threshold"`
		TotalShares int    `json:"total_shares"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		backupError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON request body")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(req.PublicKey), ""))
	if err != nil || len(raw) != recoverykey.PublicKeyBytes {
		backupError(w, http.StatusBadRequest, "invalid_key", fmt.Sprintf("public_key must be the %d-byte suite recovery public key in base64", recoverykey.PublicKeyBytes))
		return
	}
	key, err := recoveryclient.ParsePinRequest(req.PublicKey, req.Threshold, req.TotalShares)
	if err != nil {
		backupError(w, http.StatusBadRequest, "invalid_key", recoveryclient.AuditSafe(err.Error()))
		return
	}
	id := key.Public.ID()
	if err := recoveryclient.StoreRecoveryKey(s.cfg.DataDir, s.settings(), key); err != nil {
		if errors.Is(err, fs.ErrExist) {
			s.auditBackup(r, "admin.backup_key_pin", acc.ID, "failure", map[string]any{"recovery_key_id": id, "error": "already pinned to a different key"})
			backupError(w, http.StatusConflict, "key_conflict", "Already pinned to a different recovery key")
			return
		}
		s.auditBackup(r, "admin.backup_key_pin", acc.ID, "failure", map[string]any{"recovery_key_id": id, "error": err.Error()})
		backupError(w, http.StatusInternalServerError, "pin_failed", "Failed to save the recovery key")
		return
	}
	s.auditBackup(r, "admin.backup_key_pin", acc.ID, "success", map[string]any{"recovery_key_id": id, "threshold": key.Threshold, "total_shares": key.TotalShares})
	writeJSON(w, http.StatusOK, map[string]any{"recovery_key_id": id, "threshold": key.Threshold, "total_shares": key.TotalShares})
}

// handleSetSchedule stores how often the loop backs up; zero turns it off. The reply and the
// audit row describe what the store holds, never the request.
func (s *Server) handleSetSchedule(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)
	var req struct {
		IntervalSec int64 `json:"interval_sec"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		backupError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON request body")
		return
	}
	if err := recoveryclient.SetInterval(s.settings(), req.IntervalSec); err != nil {
		if errors.Is(err, recoveryclient.ErrBadInterval) {
			backupError(w, http.StatusBadRequest, "bad_interval", err.Error())
			return
		}
		backupError(w, http.StatusInternalServerError, "schedule_failed", "Failed to save the schedule")
		return
	}
	stored, err := recoveryclient.Interval(s.cfg.Backup.DepositInterval, s.settings())
	if err != nil {
		backupError(w, http.StatusInternalServerError, "schedule_failed", "Failed to read the schedule back")
		return
	}
	sec := int64(stored / time.Second)
	s.auditBackup(r, "admin.backup_schedule", acc.ID, "success", map[string]any{"interval_sec": sec})
	writeJSON(w, http.StatusOK, map[string]any{"interval_sec": sec})
}

// handleBackupStatus reports the pin, the pairing, local copies and the schedule. It never
// decrypts or echoes the credential.
func (s *Server) handleBackupStatus(w http.ResponseWriter, r *http.Request) {
	settings := s.settings()
	out := map[string]any{
		"paired":                 false,
		"key_pinned":             false,
		"app_name":               backup.AppName,
		"app_version":            s.cfg.AppVersion,
		"members":                backup.Members(s.cfg.DataDir, s.cfg.ConfigDir),
		"allow_private_recovery": s.cfg.Backup.AllowPrivateRecovery,
	}
	if u, err := s.store.GetSetting("kyrecovery_url"); err == nil {
		out["recovery_url"] = u
	}
	if key, err := recoveryclient.LoadRecoveryKey(s.cfg.DataDir, settings); err == nil {
		out["key_pinned"] = true
		out["paired"] = recoveryclient.HasPairing(settings)
		out["recovery_key_id"] = key.Public.ID()
		out["threshold"] = key.Threshold
		out["total_shares"] = key.TotalShares
	} else if errors.Is(err, recoveryclient.ErrKeyMismatch) {
		out["recovery_key_error"] = "recovery.pub does not match the pinned key ID"
	} else if recoveryclient.HasPairing(settings) {
		out["recovery_key_error"] = "paired, but recovery.pub is missing; restore it or re-pair"
	}
	if last, ok, err := recoveryclient.LastDeposit(settings); err == nil && ok {
		out["last_deposit"] = last
	}
	if s.cfg.Backup.Dir != "" {
		out["local_dir"] = s.cfg.Backup.Dir
		out["local_keep"] = s.cfg.Backup.Keep
		if copies, err := recoveryclient.ListLocalCopies(s.cfg.Backup.Dir, backup.AppName); err == nil {
			out["local_copies"] = copies
		} else {
			out["local_error"] = recoveryclient.AuditSafe(err.Error())
		}
	}
	if interval, err := recoveryclient.Interval(s.cfg.Backup.DepositInterval, settings); err == nil {
		out["interval_sec"] = int64(interval / time.Second)
		out["min_interval_sec"] = int64(recoveryclient.MinInterval / time.Second)
		if next, ok, err := recoveryclient.NextRun(s.cfg.Backup.DepositInterval, settings); err == nil && ok {
			out["next_run_at"] = next.Format(time.RFC3339)
		}
	}
	writeJSON(w, http.StatusOK, out)
}
