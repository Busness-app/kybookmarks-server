package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Entry represents a single audit event with cryptographic hash chaining.
type Entry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	UserID    string    `json:"userId,omitempty"`
	DeviceID  string    `json:"deviceId,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Details   string    `json:"details,omitempty"`
	PrevHash  string    `json:"prevHash"`
	Hash      string    `json:"hash"`
}

// Logger persists and verifies audit entries with SHA-256 hash chaining.
type Logger struct {
	mu       sync.Mutex
	filePath string
	secret   []byte
	lastHash string
}

// NewLogger initializes the audit logger.
func NewLogger(dataDir string, hmacSecret string) (*Logger, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %w", err)
	}

	secret := []byte(hmacSecret)
	if len(secret) == 0 {
		secret = []byte("kybookmarks-audit-default-secret")
	}

	l := &Logger{
		filePath: filepath.Join(dataDir, "audit.log"),
		secret:   secret,
		lastHash: "0000000000000000000000000000000000000000000000000000000000000000",
	}

	_ = l.recoverLastHash()
	return l, nil
}

func (l *Logger) recoverLastHash() error {
	entries, err := l.ReadEntries(0)
	if err != nil || len(entries) == 0 {
		return nil
	}
	l.lastHash = entries[len(entries)-1].Hash
	return nil
}

// Log writes a new event to the audit trail.
func (l *Logger) Log(action, userID, deviceID, ip, details string) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := Entry{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		UserID:    userID,
		DeviceID:  deviceID,
		IP:        ip,
		Details:   details,
		PrevHash:  l.lastHash,
	}

	entry.Hash = l.computeHash(entry)
	l.lastHash = entry.Hash

	data, err := json.Marshal(entry)
	if err != nil {
		return entry, err
	}

	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return entry, err
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		return entry, err
	}

	return entry, nil
}

func (l *Logger) computeHash(e Entry) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		e.ID,
		e.Timestamp.Format(time.RFC3339Nano),
		e.Action,
		e.UserID,
		e.DeviceID,
		e.IP,
		e.Details,
		e.PrevHash,
	)
	h := hmac.New(sha256.New, l.secret)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// ReadEntries returns audit entries up to limit (0 = all).
func (l *Logger) ReadEntries(limit int) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := os.ReadFile(l.filePath)
	if os.IsNotExist(err) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}

	var entries []Entry
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err == nil {
			entries = append(entries, e)
		}
	}

	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}

	return entries, nil
}

// VerifyChain checks the integrity of the audit chain.
func (l *Logger) VerifyChain() (bool, int, error) {
	entries, err := l.ReadEntries(0)
	if err != nil {
		return false, 0, err
	}

	expectedPrev := "0000000000000000000000000000000000000000000000000000000000000000"
	for i, e := range entries {
		if e.PrevHash != expectedPrev {
			return false, i, fmt.Errorf("hash chain broken at entry %d (%s): prevHash mismatch", i, e.ID)
		}
		computed := l.computeHash(e)
		if computed != e.Hash {
			return false, i, fmt.Errorf("hash chain broken at entry %d (%s): hash mismatch", i, e.ID)
		}
		expectedPrev = e.Hash
	}

	return true, len(entries), nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
