package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
	logFile     = "audit.log"
	keyFile     = "audit.key"
	stateFile   = "audit.state"
	keyEnv      = "AUDIT_KEY"
	keyLen      = 32

	// version0 entries predate keying: they were chained with a secret published in
	// this repository and are therefore forgeable. They are verified, never written.
	version0 = 0
	version1 = 1

	actionRekeyed = "audit.rekeyed"

	// legacyDefaultSecret is the constant this server shipped with before keying.
	// It is public and worthless as a secret; it exists only so logs written under
	// it still verify. Never use it to write an entry.
	legacyDefaultSecret = "kybookmarks-default-hmac-secret"
)

// Entry represents a single audit event with cryptographic hash chaining.
type Entry struct {
	V         int       `json:"v,omitempty"`
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

// state is the high-water mark for the chain. It lives outside the log directory
// because hashes inside a file can never detect that the file was truncated.
type state struct {
	Count int    `json:"count"`
	Hash  string `json:"hash"`
}

// Logger persists and verifies audit entries with HMAC-SHA256 hash chaining.
type Logger struct {
	mu        sync.Mutex
	filePath  string
	statePath string
	key       []byte
	legacyKey []byte
	lastHash  string
	count     int

	// stateMissing records that the high-water mark was absent while keyed entries
	// existed. Recreating it would let an append after a truncation erase the evidence.
	stateMissing bool
}

// NewLogger initializes the audit logger. dataDir holds the log; configDir holds the
// key and the truncation high-water mark, and must not be the same volume as dataDir.
// legacySecret verifies pre-keying entries and is never used to write.
func NewLogger(dataDir, configDir, legacySecret string) (*Logger, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %w", err)
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit config directory: %w", err)
	}

	key, err := loadOrCreateKey(configDir)
	if err != nil {
		return nil, err
	}
	if legacySecret == "" {
		legacySecret = legacyDefaultSecret
	}

	l := &Logger{
		filePath:  filepath.Join(dataDir, logFile),
		statePath: filepath.Join(configDir, stateFile),
		key:       key,
		legacyKey: []byte(legacySecret),
		lastHash:  genesisHash,
	}

	if err := l.recover(); err != nil {
		return nil, err
	}
	return l, nil
}

// loadOrCreateKey sources the chain key from AUDIT_KEY, else configDir/audit.key,
// else 32 fresh random bytes persisted 0600. There is deliberately no constant fallback.
func loadOrCreateKey(configDir string) ([]byte, error) {
	path := filepath.Join(configDir, keyFile)

	if env := strings.TrimSpace(os.Getenv(keyEnv)); env != "" {
		key, err := decodeKey(env)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", keyEnv, err)
		}
		return key, nil
	}

	switch data, err := os.ReadFile(path); {
	case err == nil:
		key, err := decodeKey(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return key, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("failed to read audit key: %w", err)
	}

	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate audit key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		// Another process got there first. Its key is authoritative.
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read audit key: %w", err)
		}
		return decodeKey(strings.TrimSpace(string(data)))
	}
	if err != nil {
		return nil, fmt.Errorf("failed to persist audit key: %w", err)
	}
	if _, err := f.WriteString(hex.EncodeToString(key)); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to persist audit key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("failed to persist audit key: %w", err)
	}
	return key, nil
}

func decodeKey(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("must be hex encoded (openssl rand -hex %d)", keyLen)
	}
	if len(key) < keyLen {
		return nil, fmt.Errorf("must be at least %d bytes, got %d", keyLen, len(key))
	}
	return key, nil
}

// recover restores the chain tail and, on a genuine first keying, anchors the legacy
// tail with a keyed marker so those entries can no longer be rewritten.
func (l *Logger) recover() error {
	entries, err := l.ReadEntries(0)
	if err != nil {
		return fmt.Errorf("failed to read audit log: %w", err)
	}
	if len(entries) > 0 {
		l.lastHash = entries[len(entries)-1].Hash
	}

	st, err := l.loadState()
	if err != nil {
		return err
	}
	if st != nil {
		// An interrupted write leaves the mark one behind the log. Those entries are
		// really on disk, so catch up to them; never catch down to a shorter log,
		// which is what truncation looks like and is reported by VerifyChain.
		l.count = st.Count
		if len(entries) > l.count {
			l.count = len(entries)
		}
		return nil
	}

	// No state file. That is either a first run under the new scheme, or someone
	// removed it. Only the former can be true when every entry is unkeyed.
	for _, e := range entries {
		if e.V != version0 {
			// Leave state absent; VerifyChain reports it rather than papering over it.
			l.count = len(entries)
			l.stateMissing = true
			return nil
		}
	}

	l.count = len(entries)
	if len(entries) > 0 {
		if _, err := l.Log(actionRekeyed, "", "", "", "audit chain re-keyed; entries above this marker are legacy"); err != nil {
			return fmt.Errorf("failed to anchor legacy audit chain: %w", err)
		}
		return nil
	}
	return l.saveState()
}

// Log writes a new event to the audit trail.
func (l *Logger) Log(action, userID, deviceID, ip, details string) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := Entry{
		V:         version1,
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

	// Entry first, state second. A crash between them leaves the mark one behind,
	// which fails open for the newest entry only; the reverse order would raise a
	// false truncation alarm on every interrupted write.
	l.lastHash = entry.Hash
	l.count++
	return entry, l.saveState()
}

// chainHash is the single hash definition, shared by the write and verify paths so
// they cannot drift.
func chainHash(key []byte, payload string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func (l *Logger) computeHash(e Entry) string {
	fields := []any{e.ID, e.Timestamp.Format(time.RFC3339Nano), e.Action, e.UserID, e.DeviceID, e.IP, e.Details, e.PrevHash}
	if e.V == version0 {
		return chainHash(l.legacyKey, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s", fields...))
	}
	return chainHash(l.key, fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s", append([]any{e.V}, fields...)...))
}

func (l *Logger) loadState() (*state, error) {
	data, err := os.ReadFile(l.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read audit state: %w", err)
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("failed to parse audit state: %w", err)
	}
	return &st, nil
}

// saveState advances the high-water mark. It never lowers it: letting the mark drop
// would let appends after a truncation erase the evidence.
func (l *Logger) saveState() error {
	if l.stateMissing {
		return nil
	}
	st, err := l.loadState()
	if err != nil {
		return err
	}
	if st != nil && st.Count > l.count {
		return nil
	}
	data, err := json.Marshal(state{Count: l.count, Hash: l.lastHash})
	if err != nil {
		return err
	}
	return writeFileAtomic(l.statePath, data)
}

// writeFileAtomic replaces path in one step. os.WriteFile truncates first, so a
// verifier reading concurrently can observe an empty file and cry truncation.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ReadEntries returns audit entries up to limit (0 = all).
func (l *Logger) ReadEntries(limit int) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := os.ReadFile(l.filePath)
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}

	var entries []Entry
	for _, line := range splitLines(data) {
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
	// State first, log second: the inverse of Log's write order. Reading the log
	// first lets a concurrent append make the mark outrun the entries we sampled,
	// reporting truncation on a healthy chain.
	st, err := l.loadState()
	if err != nil {
		return false, 0, err
	}

	entries, err := l.ReadEntries(0)
	if err != nil {
		return false, 0, err
	}
	switch {
	case st == nil && len(entries) > 0:
		return false, 0, errors.New("audit state is missing: the chain cannot be checked for truncation")
	case st != nil && len(entries) < st.Count:
		return false, len(entries), fmt.Errorf("audit log truncated: %d entries present, %d recorded", len(entries), st.Count)
	case st != nil && st.Count > 0 && entries[st.Count-1].Hash != st.Hash:
		return false, st.Count - 1, fmt.Errorf("audit log diverges from recorded state at entry %d", st.Count-1)
	}

	expectedPrev := genesisHash
	for i, e := range entries {
		if e.PrevHash != expectedPrev {
			return false, i, fmt.Errorf("hash chain broken at entry %d (%s): prevHash mismatch", i, e.ID)
		}
		if l.computeHash(e) != e.Hash {
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
