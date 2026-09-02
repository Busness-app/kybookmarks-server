package vault

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

var (
	ErrDepthExceeded = errors.New("folder depth exceeds maximum of 5 levels")
	ErrInvalidParent = errors.New("parent folder does not exist")
)

type Manager struct {
	db *sql.DB
	mu sync.RWMutex
}

func NewManager(s *store.Store) *Manager {
	return &Manager{db: s.DB()}
}

// syncCursor processes synchronization updates with compare-and-swap version checks.
func (m *Manager) Sync(accountID string, req store.SyncRequest) (*store.SyncResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	resp := &store.SyncResponse{
		ServerTimestamp: now,
		UpdatedObjects:  []store.VaultObject{},
		Tombstones:      []store.Tombstone{},
		Conflicts:       []store.VaultObject{},
	}

	tx, err := m.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// 1. Process client incoming changes
	for _, obj := range req.Changes {
		obj.AccountID = accountID
		obj.UpdatedAt = now

		// Check if object exists
		var currentVersion int64
		var currentDeleted int
		var currentParent string
		err := tx.QueryRow(`SELECT version, deleted, parent_id FROM vault_objects WHERE account_id = ? AND object_id = ?`,
			accountID, obj.ObjectID).Scan(&currentVersion, &currentDeleted, &currentParent)

		if errors.Is(err, sql.ErrNoRows) {
			// Brand new object insert (expected version 1)
			if obj.Version != 1 && obj.Version != 0 {
				// Conflict: client tried to update a non-existent object as if it had versions
				obj.Version = 1
			}
			if obj.Version == 0 {
				obj.Version = 1
			}

			// Validate folder depth
			if obj.ParentID != "" {
				depth, err := calculateFolderDepthTx(tx, accountID, obj.ParentID)
				if err != nil || depth >= 5 {
					resp.Conflicts = append(resp.Conflicts, obj)
					continue
				}
			}

			insertQuery := `INSERT INTO vault_objects (
				account_id, object_id, object_type, parent_id, version, position, deleted,
				ciphertext, nonce, key_wrapper, protocol_version, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
			deletedInt := 0
			if obj.Deleted {
				deletedInt = 1
			}
			_, err = tx.Exec(insertQuery,
				accountID, obj.ObjectID, obj.ObjectType, obj.ParentID, obj.Version, obj.Position,
				deletedInt, obj.Ciphertext, obj.Nonce, obj.KeyWrapper, obj.ProtocolVersion, now)
			if err != nil {
				return nil, err
			}

			// Save version history
			_, _ = tx.Exec(`INSERT INTO object_versions (account_id, object_id, version, ciphertext, nonce, key_wrapper, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				accountID, obj.ObjectID, obj.Version, obj.Ciphertext, obj.Nonce, obj.KeyWrapper, now)

			if obj.Deleted {
				exp := now.Add(90 * 24 * time.Hour)
				_, _ = tx.Exec(`INSERT OR REPLACE INTO tombstones (account_id, object_id, version, deleted_at, expires_at)
					VALUES (?, ?, ?, ?, ?)`, accountID, obj.ObjectID, obj.Version, now, exp)
			}
		} else if err == nil {
			// Existing object: Compare-and-Swap
			// The update is valid if obj.Version == currentVersion + 1
			if obj.Version <= currentVersion {
				// Version conflict / stale write! Retain client change in conflicts and versions
				resp.Conflicts = append(resp.Conflicts, obj)

				// Retain failed write for 90-day reconciliation
				_, _ = tx.Exec(`INSERT INTO object_versions (account_id, object_id, version, ciphertext, nonce, key_wrapper, created_at)
					VALUES (?, ?, ?, ?, ?, ?, ?)`,
					accountID, obj.ObjectID, obj.Version, obj.Ciphertext, obj.Nonce, obj.KeyWrapper, now)
				continue
			}

			// Validate folder depth on parent change
			if obj.ParentID != "" {
				depth, err := calculateFolderDepthTx(tx, accountID, obj.ParentID)
				if err != nil || depth >= 5 {
					resp.Conflicts = append(resp.Conflicts, obj)
					continue
				}
			}

			deletedInt := 0
			if obj.Deleted {
				deletedInt = 1
			}

			updateQuery := `UPDATE vault_objects SET
				object_type = ?, parent_id = ?, version = ?, position = ?, deleted = ?,
				ciphertext = ?, nonce = ?, key_wrapper = ?, protocol_version = ?, updated_at = ?
				WHERE account_id = ? AND object_id = ? AND version = ?`

			res, err := tx.Exec(updateQuery,
				obj.ObjectType, obj.ParentID, obj.Version, obj.Position, deletedInt,
				obj.Ciphertext, obj.Nonce, obj.KeyWrapper, obj.ProtocolVersion, now,
				accountID, obj.ObjectID, currentVersion)
			if err != nil {
				return nil, err
			}
			rowsAff, _ := res.RowsAffected()
			if rowsAff == 0 {
				resp.Conflicts = append(resp.Conflicts, obj)
				continue
			}

			// Record version history
			_, _ = tx.Exec(`INSERT INTO object_versions (account_id, object_id, version, ciphertext, nonce, key_wrapper, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				accountID, obj.ObjectID, obj.Version, obj.Ciphertext, obj.Nonce, obj.KeyWrapper, now)

			if obj.Deleted {
				exp := now.Add(90 * 24 * time.Hour)
				_, _ = tx.Exec(`INSERT OR REPLACE INTO tombstones (account_id, object_id, version, deleted_at, expires_at)
					VALUES (?, ?, ?, ?, ?)`, accountID, obj.ObjectID, obj.Version, now, exp)
			}
		}
	}

	// 2. Query updated objects since client cursor or version mismatch
	rows, err := tx.Query(`SELECT object_id, object_type, parent_id, version, position, deleted,
		ciphertext, nonce, key_wrapper, protocol_version, updated_at
		FROM vault_objects WHERE account_id = ?`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var o store.VaultObject
		var delInt int
		o.AccountID = accountID
		if err := rows.Scan(&o.ObjectID, &o.ObjectType, &o.ParentID, &o.Version, &o.Position, &delInt,
			&o.Ciphertext, &o.Nonce, &o.KeyWrapper, &o.ProtocolVersion, &o.UpdatedAt); err != nil {
			return nil, err
		}
		o.Deleted = delInt == 1

		clientVer, known := req.KnownVersions[o.ObjectID]
		if !known || clientVer < o.Version {
			resp.UpdatedObjects = append(resp.UpdatedObjects, o)
		}
	}

	// 3. Query tombstones
	tRows, err := tx.Query(`SELECT object_id, version, deleted_at, expires_at
		FROM tombstones WHERE account_id = ? AND expires_at > ?`, accountID, now)
	if err == nil {
		defer tRows.Close()
		for tRows.Next() {
			var t store.Tombstone
			t.AccountID = accountID
			if err := tRows.Scan(&t.ObjectID, &t.Version, &t.DeletedAt, &t.ExpiresAt); err == nil {
				resp.Tombstones = append(resp.Tombstones, t)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return resp, nil
}

// GetObjects returns all active or trash objects for an account.
func (m *Manager) GetObjects(accountID string, includeDeleted bool) ([]store.VaultObject, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query := `SELECT object_id, object_type, parent_id, version, position, deleted,
		ciphertext, nonce, key_wrapper, protocol_version, updated_at
		FROM vault_objects WHERE account_id = ?`
	if !includeDeleted {
		query += ` AND deleted = 0`
	}
	query += ` ORDER BY position ASC, updated_at DESC`

	rows, err := m.db.Query(query, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.VaultObject
	for rows.Next() {
		var o store.VaultObject
		var delInt int
		o.AccountID = accountID
		if err := rows.Scan(&o.ObjectID, &o.ObjectType, &o.ParentID, &o.Version, &o.Position, &delInt,
			&o.Ciphertext, &o.Nonce, &o.KeyWrapper, &o.ProtocolVersion, &o.UpdatedAt); err != nil {
			return nil, err
		}
		o.Deleted = delInt == 1
		list = append(list, o)
	}
	return list, nil
}

// GetObjectHistory returns previous retained versions for an object.
func (m *Manager) GetObjectHistory(accountID, objectID string) ([]store.ObjectVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query := `SELECT object_id, version, ciphertext, nonce, key_wrapper, created_at
		FROM object_versions WHERE account_id = ? AND object_id = ? ORDER BY version DESC LIMIT 20`

	rows, err := m.db.Query(query, accountID, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.ObjectVersion
	for rows.Next() {
		var v store.ObjectVersion
		v.AccountID = accountID
		if err := rows.Scan(&v.ObjectID, &v.Version, &v.Ciphertext, &v.Nonce, &v.KeyWrapper, &v.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, v)
	}
	return list, nil
}

func calculateFolderDepthTx(tx *sql.Tx, accountID, parentID string) (int, error) {
	depth := 1
	curr := parentID
	visited := make(map[string]bool)

	for curr != "" {
		if visited[curr] {
			return 999, errors.New("cycle detected in folder hierarchy")
		}
		visited[curr] = true
		depth++
		if depth > 5 {
			return depth, ErrDepthExceeded
		}

		var nextParent string
		err := tx.QueryRow(`SELECT parent_id FROM vault_objects WHERE account_id = ? AND object_id = ?`,
			accountID, curr).Scan(&nextParent)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return depth, err
		}
		curr = nextParent
	}
	return depth, nil
}
