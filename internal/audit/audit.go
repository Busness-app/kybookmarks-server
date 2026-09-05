package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Busness-app/ky-primitives/auditchain"
	"github.com/Busness-app/ky-primitives/keyfile"

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

	// appendTimeout bounds Append's wait for the chain lock, and nothing else. It does
	// not bound persist: persist runs with the chain lock held and no context reaches
	// it, so a hung store hangs the caller for as long as it stays hung. Log holds l.mu
	// across the whole Append, and l.chain is touched on exactly one line of this file,
	// so the chain lock is uncontended by construction and this deadline never fires.
	// It is a backstop against a second Append call site, not a live defence.
	appendTimeout = 5 * time.Second

	// legacyDefaultSecret is the constant this server shipped with before keying.
	// It is public and worthless as a secret; it exists only so logs written under
	// it still verify. Never use it to write an entry.
	legacyDefaultSecret = "kybookmarks-default-hmac-secret"
)

// ErrCorruptLog reports a log that is short of the mark *and* holds lines that do not
// decode. It names what was read, not what caused it: an undecodable line is something
// an attacker can write, so which of the two errors comes back is not evidence about
// who or what shortened the log. It is separate from ErrTruncated only so the message
// can mention the damaged lines and the remedy for them; both refuse to start.
var ErrCorruptLog = errors.New("audit: log holds lines that do not decode")

// ErrMarkNotAdvanced reports that Log wrote the record but could not advance the
// high-water mark. The entry is on disk and the chain is intact; what is missing is the
// truncation evidence for it, which recover() reconstructs on the next start once the
// config directory is writable again. It is distinct from a record-write failure so the
// operator alarm can say which happened: "was NOT recorded" about an entry that is on
// disk is the false alarm that gets real ones ignored.
var ErrMarkNotAdvanced = errors.New("audit: entry recorded, high-water mark not advanced")

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

	// tornTail records that the log does not end in a newline, so the next append must
	// terminate the fragment before adding to it. It is only ever read from the file:
	// recover() sets it from scanLog, without the lock, inside NewLogger before the
	// Logger is returned, and under mu on every later reconciliation.
	tornTail bool

	// stale reports that a write failed and l.chain may therefore no longer describe the
	// log. The next Log rebuilds it from the file before appending.
	stale bool
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
	if key, ok, err := keyfile.FromEnv(keyEnv, keyLen); err != nil {
		return nil, err
	} else if ok {
		return key, nil
	}
	return keyfile.LoadOrCreate(filepath.Join(configDir, keyFile), keyLen)
}

// recover restores the chain tail and, on a genuine first keying, anchors the legacy
// tail with a keyed marker so those entries can no longer be rewritten.
func (l *Logger) recover() error {
	sc, err := l.scanLog(0)
	if err != nil {
		return fmt.Errorf("failed to read audit log: %w", err)
	}
	entries := sc.entries
	l.tornTail = sc.torn

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

	// A log with no mark cannot be placed. The mark is the only record of how long the
	// log is meant to be, so without it a log with entries removed and one that is intact
	// are the same file — and the previous answer proved it: after deleting the mark,
	// truncating the log produced byte-identical output to not truncating it. Running on
	// with the mark absent left a detector that was on regardless of the log's contents,
	// which is not a detector.
	//
	// This is the same answer kypassword-server gives, in the same words. AGENTS.md
	// already commits this server to refusing a log emptied, filled with junk or deleted
	// outright; a missing mark is strictly worse than any of those, because it disarms the
	// check that catches them, and it was getting the gentlest response of the four.
	if st == nil && len(entries) > 0 && l.anchor.Count == 0 {
		return fmt.Errorf("audit: %w: %s holds %d records but the mark in %s counts none. "+
			"It was removed and recreated empty, or never written; either way a truncated log "+
			"cannot be told from an intact one, so this server will not start. Restore the mark "+
			"from backup, or move both files aside to begin a new chain and keep the old pair "+
			"for the auditor", auditchain.ErrBrokenChain, l.filePath, len(entries), l.statePath)
	}

	// A line that does not decode leaves the parsed count below the mark exactly as a
	// deleted record does, so reporting this file as "entries have been removed from the
	// end" told the operator one cause out of several and accused them of tampering for
	// what a power cut also produces. It cannot be told the other way either: anyone who
	// can shorten the log can add an undecodable line, so this error is a description of
	// the file, never a finding about its cause. It says both are possible and gives the
	// remedy that covers both. TestCorruptLineIsNotReportedAsTruncation pins which error
	// each file shape returns.
	if uint64(len(entries)) < l.anchor.Count && sc.corrupt > 0 {
		return fmt.Errorf("%w: %s parses to %d records but the mark in %s counts %d, "+
			"and %d line(s) in it do not decode. The log is short and damaged: a write torn by a "+
			"full disk or a crash, a corrupted block, or records removed with damage left behind -- "+
			"this server cannot tell those apart and will not start. Keep the file for the auditor, "+
			"restore the log from backup, or move both files aside to begin a new chain",
			ErrCorruptLog, l.filePath, len(entries), l.statePath, l.anchor.Count, sc.corrupt)
	}

	// Above the empty-log short-circuit, deliberately. A log emptied to zero bytes, one
	// whose lines no longer decode, and one deleted outright all read as no entries at
	// all -- the most truncated a log can be. Short-circuiting past this check answered
	// the worst case with a fresh chain that accepted appends, while a log truncated to a
	// single record was refused. Deleting the file and emptying it are the same act with
	// the same effect, so they get the same answer. So does a log whose lines no longer
	// decode -- one line above, named as the damage it is rather than as removal.
	//
	// Resuming here would mint sequence numbers that already exist -- a fork that persists
	// cleanly and can never verify again -- so refuse to start rather than append over the
	// evidence.
	if uint64(len(entries)) < l.anchor.Count {
		return fmt.Errorf("audit: %w: %s holds %d records but the mark in %s counts %d. "+
			"Entries have been removed from the end of the log; appending would write over the gap, "+
			"so this server will not start. Restore the log from backup, or move both files aside to "+
			"begin a new chain and keep the old pair for the auditor",
			auditchain.ErrTruncated, l.filePath, len(entries), l.statePath, l.anchor.Count)
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

	last := recordOf(entries[len(entries)-1], uint64(len(entries)))
	anchor := l.anchor
	overrun := l.anchor.Count > 0 && uint64(len(entries)) > l.anchor.Count

	// Resume requires an anchor naming this exact record as the tail, so every case
	// where ours does not has to be settled before the call rather than after it.
	switch {
	case overrun:
		// The mark is behind the log: records landed and the mark write that should have
		// followed did not. One behind is the classic interrupted write; several behind
		// is a config volume that was unwritable for a while, which is a disk fault and
		// not tampering, and refusing to boot on it would be refusing to boot on a full
		// disk. So walk the whole run rather than only the last of it: every record past
		// the mark must carry its own digest and must follow the one before it, starting
		// from the mark's own hash. Minting any single one of them still requires the
		// key, so accepting a run is no weaker than accepting one.
		prev := l.anchor.Hash
		for i := l.anchor.Count; i < uint64(len(entries)); i++ {
			rec := recordOf(entries[i], i+1)
			if err := auditchain.VerifyRecord(l.key, rec); err != nil {
				return fmt.Errorf("audit: %s overruns the mark in %s and record %d does not verify: %w",
					l.filePath, l.statePath, rec.Seq, err)
			}
			if rec.Prev != prev {
				return fmt.Errorf("audit: %s overruns the mark in %s and record %d does not follow its predecessor: %w",
					l.filePath, l.statePath, rec.Seq, auditchain.ErrBrokenChain)
			}
			prev = rec.Hash
		}
		anchor = auditchain.Anchor{Count: last.Seq, Hash: last.Hash}
	}

	if l.chain, err = auditchain.Resume(l.key, last, anchor); err != nil {
		return err
	}
	if overrun {
		l.anchor = anchor
		return l.saveState()
	}
	return nil
}

// converge rewrites a log written under this server's own hashing onto the shared
// package's digests. It runs once, when the log does not already carry them.
//
// Every entry must first verify under whichever digest wrote it, so a log that was
// already broken is never blessed. That is not sufficient on its own: version0 is keyed
// with legacyDefaultSecret, a constant published in this repository, so "verifies as v0"
// is a property anyone who can write the log can give it. Converting on that alone let an
// attacker with write access to dataDir swap in a chain of their own and have the next
// boot re-mint it under the real key — TestForgedLegacyLogIsNotLaunderedByConverge.
//
// So the mark decides, because it is the one input outside dataDir. When it exists the
// log must be the one it attests to: the same record count and the same tail hash. A
// mismatch converts nothing and leaves the entries in their old format, where either the
// truncation check or Resume's digest check rejects them.
//
// When there is no mark at all, there is nothing to compare against, and the only case
// that stays innocent is a genuine first run under the new scheme: every entry v0, written
// before this server had a mark to keep. With keyed v1 entries present a missing mark
// means it was removed, so nothing is converted.
func (l *Logger) converge(entries []Entry, st *state) ([]Entry, error) {
	if len(entries) == 0 {
		return entries, nil
	}
	// Is this log already in the shared digest format? That is all this asks. Resume
	// would also assert that the record is the tail, which is a different question and
	// not the one converge needs answered.
	if auditchain.VerifyRecord(l.key, recordOf(entries[len(entries)-1], uint64(len(entries)))) == nil {
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
	} else if st.Count != len(entries) || st.Hash != entries[len(entries)-1].Hash {
		// The count alone is not enough: an equal-length substitution passes it, and
		// that is the cheapest forgery to mount.
		return entries, nil
	}

	// Replay, not a per-record Append: the log is written once after the loop and the
	// anchor saved once after that, so a persist callback per record would have nothing
	// to persist.
	tuples := make([][]string, 0, len(entries))
	for _, e := range entries {
		tuples = append(tuples, fieldsOf(e))
	}
	records, anchor, err := auditchain.Replay(l.key, tuples)
	if err != nil {
		return nil, err
	}
	converted := make([]Entry, 0, len(entries))
	for i, e := range entries {
		e.PrevHash, e.Hash = records[i].Prev, records[i].Hash
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
	// The rewrite terminated every line, including any fragment the old file ended in.
	l.tornTail = false

	l.anchor = anchor
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
//
// ctx is accepted for its values, but its cancellation is deliberately dropped. Handlers
// pass r.Context(), which dies the instant the client hangs up, so honouring it would put
// the record of what a client just did under that client's control: abort the connection
// after the handler has acted and the entry is never written. The records a brute-forcing
// client most wants gone, auth.login_failed and auth.recovery_blocked, are exactly the
// ones written that way. The audit write is not the caller's to cancel.
//
// The error is the caller's to notice: it reports the record write and the mark write,
// and internal/api routes every call site through Server.auditEvent so a failure reaches
// the operator rather than the floor.
//
// The bound Append needs is a bound on a hung store, not a channel the remote end holds,
// so it is imposed here: once, where no future handler can pass the wrong context.
func (l *Logger) Log(ctx context.Context, action, userID, deviceID, ip, details string) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Before the deadline below, not after: this reads the whole log, and a budget spent
	// on it is a budget the append does not get.
	if l.stale {
		if err := l.recover(); err != nil {
			return Entry{}, fmt.Errorf("failed to reconcile the audit log after a failed write: %w", err)
		}
		l.stale = false
	}

	// Derived after the mutex, not before. l.mu is a plain sync.Mutex that no context
	// can interrupt, so a deadline started above this line is spent waiting on it: a
	// caller queued behind a hung store would reach Append with an already-dead context
	// and throw its record away. That is the suppression this context handling exists to
	// prevent, reached by load instead of by a dropped connection. Every waiter gets its
	// budget measured from the moment it can actually make progress.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appendTimeout)
	defer cancel()

	entry := Entry{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		UserID:    userID,
		DeviceID:  deviceID,
		IP:        ip,
		Details:   details,
	}

	// The only use of l.chain in this package, and it is under l.mu. That is the
	// invariant appendTimeout leans on: one call site means acquire never contends, so
	// the deadline cannot expire on a queue. A second Append call site would reintroduce
	// an unbounded wait -- TestChainIsDrivenFromOneCallSite refuses one.
	var stateErr error
	_, err := l.chain.Append(ctx, func(r auditchain.Record, a auditchain.Anchor) error {
		entry.PrevHash, entry.Hash = r.Prev, r.Hash
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}

		// A record and its terminator go out in one Write, but that is not a promise the
		// file ends in a newline: a short write on a full disk, or a crash, leaves the
		// file ending mid-record. Appending straight onto that fragment welds the two
		// into a single line that decodes as neither, so the record that *did* land is
		// lost and the parsed count sits one below the mark forever -- a permanent boot
		// failure reported as truncation. Terminating the fragment first keeps it a line
		// of its own: undecodable, but inert, because a non-record changes no count.
		// Nothing is removed. TestTornWriteDoesNotMergeIntoTheNextRecord covers this.
		line := append(data, '\n')
		if l.tornTail {
			line = append([]byte{'\n'}, line...)
		}
		_, err = f.Write(line)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			// What landed is not knowable from here, and the two branches disagree. A
			// short write leaves a fragment. A Close reporting a deferred write-back
			// failure -- EIO, ENOSPC, EDQUOT on a network- or FUSE-backed volume -- can
			// leave the complete record and its newline, and assuming a fragment there
			// mints this sequence twice: every later entry then sits one position past
			// the sequence its digest was minted for, which is a permanent boot failure
			// reported as tampering. So decide from nothing now; read the file on the
			// next Log instead, when the answer is finally on disk. That is the same
			// reconciliation recover() performs at start, and it is why a restart already
			// heals this. TestShortWriteLeavesATornTail and
			// TestFailedWriteReconcilesAgainstTheLog cover the two branches.
			l.stale = true
			return err
		}
		l.tornTail = false

		// Entry first, state second. A crash between them leaves the mark one behind,
		// which fails open for the newest entry only; the reverse order would raise a
		// false truncation alarm on every interrupted write.
		//
		// Still two writes to two files, and persist does not make them one. The chain
		// advances when the *record* write succeeds -- that is the part that was wrong
		// before. The mark write is best-effort: its failure is returned from Log, not to
		// the chain, and recover() reconciles a mark left behind however far it fell.
		//
		// A failed mark write is reported to the caller, not to the chain. The record is
		// already on disk, so refusing here would leave the chain a step behind the log
		// and the next append would reuse this sequence -- forking it permanently. A mark
		// left behind is just the interrupted write recover() reconciles.
		if a.Count > l.anchor.Count {
			l.anchor = a
			stateErr = l.saveState()
		}
		return nil
	}, fieldsOf(entry)...)
	if err != nil {
		return entry, fmt.Errorf("failed to record the audit entry: %w", err)
	}
	l.count++
	if stateErr != nil {
		return entry, fmt.Errorf("%w: %w", ErrMarkNotAdvanced, stateErr)
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

// scan is what one pass over the log file found.
type scan struct {
	entries []Entry
	// corrupt counts non-empty lines that did not decode. Skipping them silently made
	// damage indistinguishable from removal: both leave the parsed count below the mark.
	corrupt int
	// torn reports that the file does not end in a newline, so its last line is a
	// record that was only partly written.
	torn bool
}

// scanLog parses the log and reports what it could not parse.
func (l *Logger) scanLog(limit int) (scan, error) {
	var sc scan
	data, err := os.ReadFile(l.filePath)
	if errors.Is(err, os.ErrNotExist) {
		sc.entries = []Entry{}
		return sc, nil
	}
	if err != nil {
		return scan{}, err
	}
	sc.torn = len(data) > 0 && data[len(data)-1] != '\n'

	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			sc.corrupt++
			continue
		}
		sc.entries = append(sc.entries, e)
	}

	if limit > 0 && len(sc.entries) > limit {
		sc.entries = sc.entries[len(sc.entries)-limit:]
	}
	return sc, nil
}

// readEntries is ReadEntries without the lock, for callers that already hold it.
func (l *Logger) readEntries(limit int) ([]Entry, error) {
	sc, err := l.scanLog(limit)
	return sc.entries, err
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
