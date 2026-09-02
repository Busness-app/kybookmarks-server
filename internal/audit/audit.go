package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Busness-app/ky-primitives/auditchain"

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

// fieldsOf is the entry content the chain authenticates. The order is part of the
// chain format: changing it invalidates every stored digest.
func fieldsOf(e Entry) []string {
	return []string{
		e.ID,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.Action,
		e.UserID,
		e.DeviceID,
		e.IP,
		e.Details,
	}
}

// recordOf reads a stored entry as a chain record. Entries carry no sequence of
// their own; position in the log is the sequence.
func recordOf(e Entry, seq uint64) auditchain.Record {
	return auditchain.Record{Seq: seq, Prev: e.PrevHash, Hash: e.Hash, Fields: fieldsOf(e)}
}

// Logger persists and verifies audit entries with the suite's shared chain.
type Logger struct {
	mu        sync.Mutex
	filePath  string
	statePath string
	key       []byte
	legacyKey []byte
	chain     *auditchain.Chain
	anchor    auditchain.Anchor
	count     int

	// stateMissing records that the high-water mark was absent while an already
	// converted log existed. Recreating it would let an append after a truncation
	// erase the evidence.
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

	st, err := l.loadState()
	if err != nil {
		return err
	}
	if st != nil {
		l.anchor = auditchain.Anchor{Count: uint64(st.Count), Hash: st.Hash}
	}

	if entries, err = l.converge(entries, st); err != nil {
		return err
	}
	l.count = len(entries)

	// No state file, and nothing was converted: the log was already in the shared
	// format, so the mark was removed rather than never written. Leave it absent;
	// VerifyChain reports it rather than papering over it.
	if st == nil && len(entries) > 0 && l.anchor.Count == 0 {
		l.stateMissing = true
	}

	if len(entries) == 0 {
		l.chain, err = auditchain.New(l.key)
		if err != nil {
			return err
		}
		if st == nil {
			return l.saveState()
		}
		return nil
	}

	if l.chain, err = auditchain.Resume(l.key, recordOf(entries[len(entries)-1], uint64(len(entries)))); err != nil {
		return err
	}

	// An interrupted write leaves the mark one behind the log. Only a key holder
	// can produce an entry that carries its own digest, so that entry is ours;
	// catch up to it. Never catch down to a shorter log, which is what truncation
	// looks like and is reported by VerifyChain.
	if uint64(len(entries)) == l.anchor.Count+1 && l.anchor.Count > 0 {
		l.anchor = l.chain.Anchor()
		return l.saveState()
	}
	return nil
}

// converge rewrites a log written under this server's own hashing onto the shared
// package's digests. It runs once, when the log does not already carry them.
//
// Every entry must first verify under whichever digest wrote it, so a log that was
// already broken is never blessed. A missing state file is only innocent when every
// entry is unkeyed — a first run under the new scheme. With keyed entries present it
// means the mark was removed, so nothing is converted and VerifyChain reports it.
func (l *Logger) converge(entries []Entry, st *state) ([]Entry, error) {
	if len(entries) == 0 {
		return entries, nil
	}
	if _, err := auditchain.Resume(l.key, recordOf(entries[len(entries)-1], uint64(len(entries)))); err == nil {
		return entries, nil
	}

	versions, ok := l.legacyVersions(entries)
	if !ok {
		return entries, nil
	}
	if st == nil {
		for _, v := range versions {
			if v != version0 {
				return entries, nil
			}
		}
	}

	chain, err := auditchain.New(l.key)
	if err != nil {
		return nil, err
	}
	converted := make([]Entry, 0, len(entries))
	for _, e := range entries {
		rec, err := chain.Append(fieldsOf(e)...)
		if err != nil {
			return nil, err
		}
		e.PrevHash, e.Hash = rec.Prev, rec.Hash
		converted = append(converted, e)
	}

	var buf []byte
	for _, e := range converted {
		data, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		buf = append(append(buf, data...), '\n')
	}
	if err := writeFileAtomic(l.filePath, buf); err != nil {
		return nil, err
	}

	l.anchor = chain.Anchor()
	if err := l.saveState(); err != nil {
		return nil, err
	}
	return converted, nil
}

// legacyVersions reports the format each entry was written under, or false if any
// entry does not match either.
func (l *Logger) legacyVersions(entries []Entry) ([]int, bool) {
	versions := make([]int, 0, len(entries))
	prev := genesisHash
	for _, e := range entries {
		if e.PrevHash != prev {
			return nil, false
		}
		switch e.Hash {
		case l.legacyHash(e, version1):
			versions = append(versions, version1)
		case l.legacyHash(e, version0):
			versions = append(versions, version0)
		default:
			return nil, false
		}
		prev = e.Hash
	}
	return versions, true
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
	}

	rec, err := l.chain.Append(fieldsOf(entry)...)
	if err != nil {
		return entry, fmt.Errorf("failed to extend the audit chain: %w", err)
	}
	entry.PrevHash, entry.Hash = rec.Prev, rec.Hash

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
	l.count++
	if a := l.chain.Anchor(); a.Count > l.anchor.Count && !l.stateMissing {
		l.anchor = a
		return entry, l.saveState()
	}
	return entry, nil
}

// chainHash is the single hash definition, shared by the write and verify paths so
// they cannot drift.
func chainHash(key []byte, payload string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// legacyHash is the digest this server used before the chain moved to the shared
// format. Both variants joined the fields with a bare "|", so content carrying the
// delimiter could be shifted into a neighbouring field without changing the digest.
//
// Deprecated: retained only to recognise entries written that way. New entries are
// written by auditchain.
func (l *Logger) legacyHash(e Entry, version int) string {
	fields := []any{e.ID, e.Timestamp.Format(time.RFC3339Nano), e.Action, e.UserID, e.DeviceID, e.IP, e.Details, e.PrevHash}
	if version == version0 {
		return chainHash(l.legacyKey, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s", fields...))
	}
	return chainHash(l.key, fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s", append([]any{version}, fields...)...))
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
	if st != nil && uint64(st.Count) > l.anchor.Count {
		return nil
	}
	data, err := json.Marshal(state{Count: int(l.anchor.Count), Hash: l.anchor.Hash})
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
	return l.readEntries(limit)
}

// readEntries is ReadEntries without the lock, for callers that already hold it.
func (l *Logger) readEntries(limit int) ([]Entry, error) {
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

// VerifyChain checks the integrity of the audit chain against the recorded anchor.
func (l *Logger) VerifyChain() (bool, int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := l.readEntries(0)
	if err != nil {
		return false, 0, err
	}

	records := make([]auditchain.Record, 0, len(entries))
	for i, e := range entries {
		records = append(records, recordOf(e, uint64(i+1)))
	}

	if err := auditchain.Verify(l.key, records, l.anchor); err != nil {
		return false, len(entries), err
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

// ExportChain writes the log as shared-package records, and returns the anchor to
// check them against. This is the form kyauditverify reads: the products store
// different fields, so the records as the chain sees them are the only thing one
// verifier can consume from all of them.
func (l *Logger) ExportChain(w io.Writer) (auditchain.Anchor, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := l.readEntries(0)
	if err != nil {
		return auditchain.Anchor{}, err
	}
	enc := json.NewEncoder(w)
	for i, e := range entries {
		if err := enc.Encode(recordOf(e, uint64(i+1))); err != nil {
			return auditchain.Anchor{}, err
		}
	}
	return l.anchor, nil
}
