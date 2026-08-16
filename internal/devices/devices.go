package devices

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	"kybookmarks-server/internal/crypto"
	"kybookmarks-server/internal/store"

	"github.com/google/uuid"
)

var (
	ErrPairingExpired   = errors.New("pairing session expired or not found")
	ErrNotApproved      = errors.New("pairing session not yet approved")
	ErrAlreadyRedeemed  = errors.New("pairing session already redeemed")
	ErrInvalidPIN       = errors.New("invalid pairing PIN")
)

type Store struct {
	db *sql.DB
	mu sync.RWMutex
}

func NewStore(s *store.Store) *Store {
	return &Store{db: s.DB()}
}

// RequestPairing creates a new 90-second pairing session with PIN and token.
func (s *Store) RequestPairing(userID, deviceName, deviceType string) (*store.PairingSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pin, err := crypto.GeneratePIN()
	if err != nil {
		return nil, err
	}
	token, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	sess := &store.PairingSession{
		ID:           uuid.NewString(),
		PIN:          pin,
		PairingToken: token,
		UserID:       userID,
		DeviceName:   deviceName,
		DeviceType:   deviceType,
		ExpiresAt:    now.Add(90 * time.Second),
		CreatedAt:    now,
	}

	query := `INSERT INTO pairing_sessions (id, pin, pairing_token, user_id, device_name, device_type, approved, redeemed, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`
	_, err = s.db.Exec(query, sess.ID, sess.PIN, sess.PairingToken, sess.UserID, sess.DeviceName, sess.DeviceType, sess.ExpiresAt, sess.CreatedAt)
	if err != nil {
		return nil, err
	}

	return sess, nil
}

// ApprovePairing is called by an already trusted device to grant vault key envelope.
func (s *Store) ApprovePairing(pin, vaultKeyEnvelope string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	query := `UPDATE pairing_sessions SET approved = 1, vault_key_envelope = ?
		WHERE pin = ? AND expires_at > ? AND approved = 0`
	res, err := s.db.Exec(query, vaultKeyEnvelope, pin, now)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrInvalidPIN
	}
	return nil
}

// RedeemPairing is called by the new device polling for approval.
func (s *Store) RedeemPairing(token, publicKey string) (*store.PairingSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var sess store.PairingSession
	var env, pk sql.NullString
	var app, red int

	query := `SELECT id, pin, pairing_token, user_id, device_name, device_type, public_key, vault_key_envelope,
		approved, redeemed, expires_at, created_at FROM pairing_sessions WHERE pairing_token = ? AND expires_at > ?`

	err := s.db.QueryRow(query, token, now).Scan(
		&sess.ID, &sess.PIN, &sess.PairingToken, &sess.UserID, &sess.DeviceName, &sess.DeviceType,
		&pk, &env, &app, &red, &sess.ExpiresAt, &sess.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPairingExpired
	}
	if err != nil {
		return nil, err
	}

	sess.PublicKey = pk.String
	sess.VaultKeyEnvelope = env.String
	sess.Approved = app == 1
	sess.Redeemed = red == 1

	if !sess.Approved {
		return nil, ErrNotApproved
	}
	if sess.Redeemed {
		return nil, ErrAlreadyRedeemed
	}

	_, _ = s.db.Exec(`UPDATE pairing_sessions SET redeemed = 1, public_key = ? WHERE id = ?`, publicKey, sess.ID)
	return &sess, nil
}
