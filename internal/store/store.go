package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound       = errors.New("record not found")
	ErrConflict       = errors.New("version conflict")
	ErrAlreadyExists  = errors.New("record already exists")
	ErrAccountBlocked = errors.New("account suspended or disabled")
)

type Store struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewStore creates or opens the SQLite database and executes migrations.
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "kybookmarks.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// DB returns the underlying sql.DB.
func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS accounts (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		display_name TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		auth_salt TEXT NOT NULL,
		kdf_iterations INTEGER NOT NULL DEFAULT 600000,
		role TEXT NOT NULL DEFAULT 'user',
		status TEXT NOT NULL DEFAULT 'active',
		sso_subject TEXT UNIQUE,
		password_key_wrap TEXT,
		recovery_key_wrap TEXT,
		recovery_verifier TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token_hash TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
		device_id TEXT,
		csrf_token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

	CREATE TABLE IF NOT EXISTS devices (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
		device_name TEXT NOT NULL,
		device_type TEXT NOT NULL,
		public_key TEXT,
		key_envelope TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		last_seen_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);

	CREATE TABLE IF NOT EXISTS pairing_sessions (
		id TEXT PRIMARY KEY,
		pin TEXT NOT NULL,
		pairing_token TEXT UNIQUE NOT NULL,
		user_id TEXT NOT NULL,
		device_name TEXT NOT NULL,
		device_type TEXT NOT NULL,
		public_key TEXT,
		vault_key_envelope TEXT,
		approved INTEGER NOT NULL DEFAULT 0,
		redeemed INTEGER NOT NULL DEFAULT 0,
		expires_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_pairing_pin ON pairing_sessions(pin);
	CREATE INDEX IF NOT EXISTS idx_pairing_token ON pairing_sessions(pairing_token);

	CREATE TABLE IF NOT EXISTS vault_objects (
		account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
		object_id TEXT NOT NULL,
		object_type TEXT NOT NULL,
		parent_id TEXT NOT NULL DEFAULT '',
		version INTEGER NOT NULL DEFAULT 1,
		position INTEGER NOT NULL DEFAULT 0,
		deleted INTEGER NOT NULL DEFAULT 0,
		ciphertext TEXT NOT NULL,
		nonce TEXT NOT NULL,
		key_wrapper TEXT NOT NULL,
		protocol_version INTEGER NOT NULL DEFAULT 1,
		updated_at DATETIME NOT NULL,
		PRIMARY KEY(account_id, object_id)
	);
	CREATE INDEX IF NOT EXISTS idx_vault_parent ON vault_objects(account_id, parent_id);
	CREATE INDEX IF NOT EXISTS idx_vault_updated ON vault_objects(account_id, updated_at);

	CREATE TABLE IF NOT EXISTS object_versions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		account_id TEXT NOT NULL,
		object_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		ciphertext TEXT NOT NULL,
		nonce TEXT NOT NULL,
		key_wrapper TEXT NOT NULL,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_obj_versions ON object_versions(account_id, object_id, version);

	CREATE TABLE IF NOT EXISTS tombstones (
		account_id TEXT NOT NULL,
		object_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		deleted_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		PRIMARY KEY(account_id, object_id)
	);
	CREATE INDEX IF NOT EXISTS idx_tombstones_exp ON tombstones(expires_at);
	`
	_, err := s.db.Exec(schema)
	return err
}

// Account methods

func (s *Store) CreateAccount(a *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	a.CreatedAt = now
	a.UpdatedAt = now
	if a.KDFIterations == 0 {
		a.KDFIterations = 600000
	}
	if a.Role == "" {
		a.Role = "user"
	}
	if a.Status == "" {
		a.Status = "active"
	}

	query := `INSERT INTO accounts (
		id, username, email, display_name, password_hash, auth_salt, kdf_iterations,
		role, status, sso_subject, password_key_wrap, recovery_key_wrap, recovery_verifier,
		created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		a.ID, strings.ToLower(a.Username), strings.ToLower(a.Email), a.DisplayName,
		a.PasswordHash, a.AuthSalt, a.KDFIterations, a.Role, a.Status, a.SSOSubject,
		a.PasswordKeyWrap, a.RecoveryKeyWrap, a.RecoveryVerifier, a.CreatedAt, a.UpdatedAt,
	)
	return err
}

func (s *Store) GetAccountByID(id string) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, username, email, display_name, password_hash, auth_salt, kdf_iterations,
		role, status, sso_subject, password_key_wrap, recovery_key_wrap, recovery_verifier,
		created_at, updated_at FROM accounts WHERE id = ?`

	var a Account
	var ssoSub, pWrap, rWrap, rVer sql.NullString
	err := s.db.QueryRow(query, id).Scan(
		&a.ID, &a.Username, &a.Email, &a.DisplayName, &a.PasswordHash, &a.AuthSalt, &a.KDFIterations,
		&a.Role, &a.Status, &ssoSub, &pWrap, &rWrap, &rVer, &a.CreatedAt, &a.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	a.SSOSubject = ssoSub.String
	a.PasswordKeyWrap = pWrap.String
	a.RecoveryKeyWrap = rWrap.String
	a.RecoveryVerifier = rVer.String
	return &a, nil
}

func (s *Store) GetAccountByUsernameOrEmail(identifier string) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clean := strings.ToLower(strings.TrimSpace(identifier))
	query := `SELECT id, username, email, display_name, password_hash, auth_salt, kdf_iterations,
		role, status, sso_subject, password_key_wrap, recovery_key_wrap, recovery_verifier,
		created_at, updated_at FROM accounts WHERE username = ? OR email = ?`

	var a Account
	var ssoSub, pWrap, rWrap, rVer sql.NullString
	err := s.db.QueryRow(query, clean, clean).Scan(
		&a.ID, &a.Username, &a.Email, &a.DisplayName, &a.PasswordHash, &a.AuthSalt, &a.KDFIterations,
		&a.Role, &a.Status, &ssoSub, &pWrap, &rWrap, &rVer, &a.CreatedAt, &a.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	a.SSOSubject = ssoSub.String
	a.PasswordKeyWrap = pWrap.String
	a.RecoveryKeyWrap = rWrap.String
	a.RecoveryVerifier = rVer.String
	return &a, nil
}

func (s *Store) GetAccountBySSOSubject(sub string) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, username, email, display_name, password_hash, auth_salt, kdf_iterations,
		role, status, sso_subject, password_key_wrap, recovery_key_wrap, recovery_verifier,
		created_at, updated_at FROM accounts WHERE sso_subject = ?`

	var a Account
	var ssoSub, pWrap, rWrap, rVer sql.NullString
	err := s.db.QueryRow(query, sub).Scan(
		&a.ID, &a.Username, &a.Email, &a.DisplayName, &a.PasswordHash, &a.AuthSalt, &a.KDFIterations,
		&a.Role, &a.Status, &ssoSub, &pWrap, &rWrap, &rVer, &a.CreatedAt, &a.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	a.SSOSubject = ssoSub.String
	a.PasswordKeyWrap = pWrap.String
	a.RecoveryKeyWrap = rWrap.String
	a.RecoveryVerifier = rVer.String
	return &a, nil
}

func (s *Store) ListAccounts() ([]Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, username, email, display_name, password_hash, auth_salt, kdf_iterations,
		role, status, sso_subject, password_key_wrap, recovery_key_wrap, recovery_verifier,
		created_at, updated_at FROM accounts ORDER BY username ASC`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Account
	for rows.Next() {
		var a Account
		var ssoSub, pWrap, rWrap, rVer sql.NullString
		if err := rows.Scan(
			&a.ID, &a.Username, &a.Email, &a.DisplayName, &a.PasswordHash, &a.AuthSalt, &a.KDFIterations,
			&a.Role, &a.Status, &ssoSub, &pWrap, &rWrap, &rVer, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		a.SSOSubject = ssoSub.String
		a.PasswordKeyWrap = pWrap.String
		a.RecoveryKeyWrap = rWrap.String
		a.RecoveryVerifier = rVer.String
		list = append(list, a)
	}
	return list, nil
}

func (s *Store) CountAccounts() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&count)
	return count, err
}

func (s *Store) UpdateAccount(a *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a.UpdatedAt = time.Now().UTC()
	query := `UPDATE accounts SET display_name = ?, role = ?, status = ?, password_hash = ?,
		auth_salt = ?, kdf_iterations = ?, sso_subject = ?, password_key_wrap = ?,
		recovery_key_wrap = ?, recovery_verifier = ?, updated_at = ? WHERE id = ?`

	_, err := s.db.Exec(query,
		a.DisplayName, a.Role, a.Status, a.PasswordHash, a.AuthSalt, a.KDFIterations,
		a.SSOSubject, a.PasswordKeyWrap, a.RecoveryKeyWrap, a.RecoveryVerifier, a.UpdatedAt, a.ID,
	)
	return err
}

func (s *Store) DeleteAccount(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM accounts WHERE id = ?`, id)
	return err
}

// Session methods

func (s *Store) CreateSession(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO sessions (token_hash, user_id, device_id, csrf_token, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, sess.TokenHash, sess.UserID, sess.DeviceID, sess.CSRFToken, sess.ExpiresAt, sess.CreatedAt)
	return err
}

func (s *Store) GetSession(tokenHash string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT token_hash, user_id, device_id, csrf_token, expires_at, created_at
		FROM sessions WHERE token_hash = ? AND expires_at > ?`

	var sess Session
	var devID sql.NullString
	err := s.db.QueryRow(query, tokenHash, time.Now().UTC()).Scan(
		&sess.TokenHash, &sess.UserID, &devID, &sess.CSRFToken, &sess.ExpiresAt, &sess.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.DeviceID = devID.String
	return &sess, nil
}

func (s *Store) DeleteSession(tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) DeleteUserSessions(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// Device methods

func (s *Store) CreateDevice(d *Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if d.ID == "" {
		d.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	d.CreatedAt = now
	d.LastSeenAt = now
	d.Status = "active"

	query := `INSERT INTO devices (id, user_id, device_name, device_type, public_key, key_envelope, status, last_seen_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, d.ID, d.UserID, d.DeviceName, d.DeviceType, d.PublicKey, d.KeyEnvelope, d.Status, d.LastSeenAt, d.CreatedAt)
	return err
}

func (s *Store) ListDevices(userID string) ([]Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, user_id, device_name, device_type, public_key, key_envelope, status, last_seen_at, created_at
		FROM devices WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Device
	for rows.Next() {
		var d Device
		var pk, env sql.NullString
		if err := rows.Scan(&d.ID, &d.UserID, &d.DeviceName, &d.DeviceType, &pk, &env, &d.Status, &d.LastSeenAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.PublicKey = pk.String
		d.KeyEnvelope = env.String
		list = append(list, d)
	}
	return list, nil
}

func (s *Store) RevokeDevice(userID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`UPDATE devices SET status = 'revoked' WHERE id = ? AND user_id = ?`, deviceID, userID)
	return err
}
