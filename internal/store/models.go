package store

import (
	"time"
)

// Account represents a user in KyBookmarks.
type Account struct {
	ID               string    `json:"id"`
	Username         string    `json:"username"`
	Email            string    `json:"email"`
	DisplayName      string    `json:"displayName"`
	PasswordHash     string    `json:"-"`
	AuthSalt         string    `json:"authSalt"`
	KDFIterations    int       `json:"kdfIterations"`
	Role             string    `json:"role"`   // "admin" | "user"
	Status           string    `json:"status"` // "active" | "suspended"
	SSOSubject       string    `json:"ssoSubject,omitempty"`
	PasswordKeyWrap  string    `json:"passwordKeyWrap,omitempty"`  // Wrapped vault key under master password
	RecoveryKeyWrap  string    `json:"recoveryKeyWrap,omitempty"`  // Wrapped vault key under paper recovery key
	RecoveryVerifier string    `json:"recoveryVerifier,omitempty"` // Hash of paper recovery key
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

// Session represents an active authenticated session.
type Session struct {
	TokenHash string    `json:"tokenHash"`
	UserID    string    `json:"userId"`
	DeviceID  string    `json:"deviceId,omitempty"`
	CSRFToken string    `json:"csrfToken"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// Device represents a registered client device.
type Device struct {
	ID          string    `json:"id"`
	UserID      string    `json:"userId"`
	DeviceName  string    `json:"deviceName"`
	DeviceType  string    `json:"deviceType"` // "browser_chrome" | "browser_firefox" | "mobile_ios" | "mobile_android" | "web"
	PublicKey   string    `json:"publicKey,omitempty"`
	KeyEnvelope string    `json:"keyEnvelope,omitempty"` // Vault key encrypted for this device
	Status      string    `json:"status"`                // "active" | "revoked"
	LastSeenAt  time.Time `json:"lastSeenAt"`
	CreatedAt   time.Time `json:"createdAt"`
}

// VaultObject represents an opaque encrypted bookmark or folder.
type VaultObject struct {
	AccountID       string    `json:"accountId"`
	ObjectID        string    `json:"objectId"`
	ObjectType      string    `json:"objectType"` // "bookmark" | "folder"
	ParentID        string    `json:"parentId"`   // UUID or "" for root
	Version         int64     `json:"version"`
	Position        int       `json:"position"`
	Deleted         bool      `json:"deleted"`
	Ciphertext      string    `json:"ciphertext"` // Encrypted object payload
	Nonce           string    `json:"nonce"`
	KeyWrapper      string    `json:"keyWrapper"` // Per-object key wrapped under vault key
	ProtocolVersion int       `json:"protocolVersion"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// ObjectVersion represents a historic version retained for 90 days.
type ObjectVersion struct {
	AccountID  string    `json:"accountId"`
	ObjectID   string    `json:"objectId"`
	Version    int64     `json:"version"`
	Ciphertext string    `json:"ciphertext"`
	Nonce      string    `json:"nonce"`
	KeyWrapper string    `json:"keyWrapper"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Tombstone prevents stale offline resurrection.
type Tombstone struct {
	AccountID string    `json:"accountId"`
	ObjectID  string    `json:"objectId"`
	Version   int64     `json:"version"`
	DeletedAt time.Time `json:"deletedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// PairingSession represents an ephemeral 90s device enrollment.
type PairingSession struct {
	ID               string    `json:"id"`
	PIN              string    `json:"pin"`
	PairingToken     string    `json:"pairingToken"`
	UserID           string    `json:"userId"`
	DeviceName       string    `json:"deviceName"`
	DeviceType       string    `json:"deviceType"`
	PublicKey        string    `json:"publicKey,omitempty"`
	VaultKeyEnvelope string    `json:"vaultKeyEnvelope,omitempty"`
	Approved         bool      `json:"approved"`
	Redeemed         bool      `json:"redeemed"`
	ExpiresAt        time.Time `json:"expiresAt"`
	CreatedAt        time.Time `json:"createdAt"`
}

// SyncCursorRequest sent by client to retrieve changes.
type SyncRequest struct {
	SinceTimestamp time.Time          `json:"sinceTimestamp"`
	KnownVersions  map[string]int64   `json:"knownVersions"` // objectId -> client version
	Changes        []VaultObject      `json:"changes"`       // Objects client wants to write
}

// SyncResponse returned to client.
type SyncResponse struct {
	ServerTimestamp time.Time     `json:"serverTimestamp"`
	UpdatedObjects  []VaultObject `json:"updatedObjects"`
	Tombstones      []Tombstone   `json:"tombstones"`
	Conflicts       []VaultObject `json:"conflicts"` // Failed concurrent writes retained for reconciliation
}
