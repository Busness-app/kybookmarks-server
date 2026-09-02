package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/auditchain"
	"time"
)

// newTestLogger builds a logger over fresh data/config dirs under root.
func newTestLogger(t *testing.T, root string) *Logger {
	t.Helper()
	l, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	return l
}

func mustLog(t *testing.T, l *Logger, action string) Entry {
	t.Helper()
	e, err := l.Log(context.Background(), action, "user-1", "device-1", "127.0.0.1", "detail")
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	return e
}

func mustVerify(t *testing.T, l *Logger, want bool, why string) {
	t.Helper()
	valid, _, err := l.VerifyChain()
	if valid != want {
		t.Fatalf("%s: VerifyChain valid=%v, want %v (err=%v)", why, valid, want, err)
	}
}

// The key must be generated per install, never a constant compiled into the binary.
func TestKeyIsNotAConstant(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	la, lb := newTestLogger(t, a), newTestLogger(t, b)

	if string(la.key) == string(lb.key) {
		t.Fatal("two fresh installs derived the same audit key")
	}
	if len(la.key) < keyLen {
		t.Fatalf("generated key is %d bytes, want >= %d", len(la.key), keyLen)
	}

	keyPath := filepath.Join(a, "config", keyFile)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key was not persisted: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("key file mode %v, want 0600", info.Mode().Perm())
	}

	// The key must survive a restart, or every restart orphans the chain.
	mustLog(t, la, "auth.login")
	restarted := newTestLogger(t, a)
	if string(restarted.key) != string(la.key) {
		t.Fatal("key was not reused across restart")
	}
	mustVerify(t, restarted, true, "after restart")
}

// The attack the published constant enabled: rewrite a record, recompute every hash
// forward with the public key, and have verification still pass.
func TestForgeryWithPublishedKeyIsRejected(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")
	mustLog(t, l, "admin.user_deleted")
	mustLog(t, l, "auth.logout")
	mustVerify(t, l, true, "before tampering")

	logPath := filepath.Join(root, "audit", logFile)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var entries []Entry
	for _, line := range splitLines(data) {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}

	// Attacker knows only what the repository publishes.
	forger := &Logger{key: []byte(legacyDefaultSecret), legacyKey: []byte(legacyDefaultSecret)}
	entries[1].Action = "auth.login"
	entries[1].Details = "nothing to see here"
	prev := entries[0].Hash
	for i := 1; i < len(entries); i++ {
		entries[i].PrevHash = prev
		entries[i].Hash = forger.legacyHash(entries[i], version1)
		prev = entries[i].Hash
	}

	var buf strings.Builder
	for _, e := range entries {
		b, _ := json.Marshal(e)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(logPath, []byte(buf.String()), 0600); err != nil {
		t.Fatal(err)
	}
	// Repair the high-water mark to match the forgery. Without this the truncation
	// check alone rejects the log and the test would pass even with a public key.
	st, _ := json.Marshal(state{Count: len(entries), Hash: entries[len(entries)-1].Hash})
	if err := os.WriteFile(filepath.Join(root, "config", stateFile), st, 0600); err != nil {
		t.Fatal(err)
	}

	mustVerify(t, l, false, "after forging with the published key")
}

// Hashes inside the file can never detect truncation: what remains still chains.
func TestTruncationIsDetected(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
		mustLog(t, l, a)
	}
	mustVerify(t, l, true, "before truncation")

	logPath := filepath.Join(root, "audit", logFile)
	data, _ := os.ReadFile(logPath)
	lines := splitLines(data)
	kept := append([]byte{}, []byte(string(lines[0])+"\n"+string(lines[1])+"\n")...)
	if err := os.WriteFile(logPath, kept, 0600); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, l, false, "after dropping the last entry")

	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, l, false, "after emptying the log")
}

// A truncated log must not be repaired by restarting. The logger used to resume from
// whatever record was left and go on appending, which forked the chain at a sequence
// that already existed; it now refuses to start, and the refusal is repeatable.
func TestTruncationIsRefusedOnRestart(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
		mustLog(t, l, a)
	}

	logPath := filepath.Join(root, "audit", logFile)
	data, _ := os.ReadFile(logPath)
	lines := splitLines(data)
	_ = os.WriteFile(logPath, []byte(string(lines[0])+"\n"), 0600)

	for _, why := range []string{"first restart", "second restart"} {
		_, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
		if !errors.Is(err, auditchain.ErrTruncated) {
			t.Fatalf("%s on a truncated log: err=%v, want ErrTruncated", why, err)
		}
	}
}

// Deleting the state file is tampering, not a fresh start.
func TestMissingStateIsNotSelfHealed(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")

	if err := os.Remove(filepath.Join(root, "config", stateFile)); err != nil {
		t.Fatal(err)
	}
	restarted := newTestLogger(t, root)
	mustVerify(t, restarted, false, "state file deleted")

	// Appending must not recreate the mark: that would launder a truncated log.
	mustLog(t, restarted, "auth.logout")
	mustVerify(t, restarted, false, "state file deleted, then appended to")
	if _, err := os.Stat(filepath.Join(root, "config", stateFile)); !os.IsNotExist(err) {
		t.Fatal("append recreated the deleted audit state")
	}
}

// The mark records the furthest the chain ever reached; a stale writer must not lower it.
func TestHighWaterMarkNeverDrops(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
		mustLog(t, l, a)
	}

	// saveState writes the anchor, so lowering count alone would exercise nothing.
	stale := newTestLogger(t, root)
	stale.anchor = auditchain.Anchor{Count: 1, Hash: stale.anchor.Hash}
	if err := stale.saveState(); err != nil {
		t.Fatal(err)
	}

	st, err := l.loadState()
	if err != nil || st == nil {
		t.Fatalf("loadState: %v", err)
	}
	if st.Count != 3 {
		t.Fatalf("high-water mark dropped to %d, want 3", st.Count)
	}
}

// writeLegacyLog writes entries in the pre-migration format, keyed with the published constant.
func writeLegacyLog(t *testing.T, root string, actions ...string) []Entry {
	t.Helper()
	dir := filepath.Join(root, "audit")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := &Logger{legacyKey: []byte(legacyDefaultSecret)}
	prev := genesisHash
	var out []Entry
	var buf strings.Builder
	for i, a := range actions {
		e := Entry{
			ID:        "legacy-" + a,
			Timestamp: time.Unix(int64(1700000000+i), 0).UTC(),
			Action:    a,
			UserID:    "user-1",
			PrevHash:  prev,
		}
		e.Hash = legacy.legacyHash(e, version0)
		prev = e.Hash
		b, _ := json.Marshal(e)
		buf.Write(b)
		buf.WriteByte('\n')
		out = append(out, e)
	}
	if err := os.WriteFile(filepath.Join(dir, logFile), []byte(buf.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return out
}

// Existing logs keep verifying after conversion, with their events intact, and can
// no longer be rewritten under the published key.
func TestLegacyLogIsPreservedAndConverted(t *testing.T) {
	root := t.TempDir()
	legacy := writeLegacyLog(t, root, "auth.login", "admin.user_deleted")

	l := newTestLogger(t, root)
	mustVerify(t, l, true, "after migration")

	entries, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(legacy) {
		t.Fatalf("got %d entries after migration, want %d", len(entries), len(legacy))
	}
	for i, e := range entries {
		if e.Action != legacy[i].Action || e.ID != legacy[i].ID {
			t.Fatalf("entry %d changed: %+v, want the original event", i, e)
		}
		if e.Hash == legacy[i].Hash {
			t.Fatalf("entry %d still carries its pre-conversion digest", i)
		}
	}

	// Restarting must not convert again or append anything.
	restarted := newTestLogger(t, root)
	again, _ := restarted.ReadEntries(0)
	if len(again) != len(entries) {
		t.Fatalf("restart changed the log by %d entries", len(again)-len(entries))
	}
	mustVerify(t, restarted, true, "after restart")

	// Rewriting a record with the published key must now be rejected.
	forger := &Logger{key: []byte(legacyDefaultSecret), legacyKey: []byte(legacyDefaultSecret)}
	tampered := entries[1]
	tampered.Action = "auth.login"
	tampered.Hash = forger.legacyHash(tampered, version1)
	b, _ := json.Marshal(tampered)
	first, _ := json.Marshal(entries[0])
	out := string(first) + "\n" + string(b) + "\n"
	if err := os.WriteFile(filepath.Join(root, "audit", logFile), []byte(out), 0600); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, restarted, false, "record rewritten under the published key")
}

func TestAuditKeyEnvMustBeStrong(t *testing.T) {
	root := t.TempDir()
	t.Setenv(keyEnv, "hunter2")
	if _, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), ""); err == nil {
		t.Fatal("NewLogger accepted a short AUDIT_KEY")
	}
}

// A crash between the entry write and the state write leaves the mark one behind.
// The next start must reconcile to the log, not stay behind it forever.
func TestStateCatchesUpAfterInterruptedWrite(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
		mustLog(t, l, a)
	}
	entries, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the crash: the third entry is on disk, the mark still says two.
	behind, _ := json.Marshal(state{Count: 2, Hash: entries[1].Hash})
	statePath := filepath.Join(root, "config", stateFile)
	if err := os.WriteFile(statePath, behind, 0600); err != nil {
		t.Fatal(err)
	}

	restarted := newTestLogger(t, root)
	mustVerify(t, restarted, true, "restart after an interrupted write")

	mustLog(t, restarted, "auth.login")
	mustVerify(t, restarted, true, "append after an interrupted write")

	st, err := restarted.loadState()
	if err != nil || st == nil {
		t.Fatalf("loadState: %v", err)
	}
	if st.Count != 4 {
		t.Fatalf("mark stuck at %d after catching up, want 4", st.Count)
	}
}

// Verification must not report truncation just because a write landed mid-check.
func TestVerifyChainIsNotRacedByConcurrentAppends(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			if _, err := l.Log(context.Background(), "auth.login", "u", "d", "127.0.0.1", "x"); err != nil {
				t.Error(err)
				return
			}
		}
	}()

	for i := 0; i < 500; i++ {
		if valid, _, err := l.VerifyChain(); !valid {
			t.Fatalf("VerifyChain reported an invalid chain during concurrent appends: %v", err)
		}
	}
	<-done
}

// A truncate-in-place rewrite lets a concurrent verifier read a half-written state
// file. Replacement by rename is observable as a different file identity.
func TestStateIsReplacedNotRewrittenInPlace(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")

	path := filepath.Join(root, "config", stateFile)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	mustLog(t, l, "auth.logout")

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("audit state was rewritten in place; a concurrent verifier can observe it empty")
	}
	if after.Mode().Perm() != 0600 {
		t.Errorf("replaced audit state has mode %v, want 0600", after.Mode().Perm())
	}
}

// The exported form must verify with nothing but the shared package: that is what
// makes one verifier possible across products that store different fields.
func TestExportedChainVerifiesWithSharedPackageAlone(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")
	mustLog(t, l, "vault.sync")

	var buf bytes.Buffer
	anchor, err := l.ExportChain(&buf)
	if err != nil {
		t.Fatalf("ExportChain failed: %v", err)
	}

	var recs []auditchain.Record
	dec := json.NewDecoder(&buf)
	for {
		var r auditchain.Record
		if err := dec.Decode(&r); err != nil {
			break
		}
		recs = append(recs, r)
	}
	if err := auditchain.Verify(l.key, recs, anchor); err != nil {
		t.Fatalf("exported chain does not verify: %v", err)
	}
}

// Conversion rewrites the log in place and stamps a fresh anchor, so it must run
// only on a log that verifies under one of the digests that could have written it.
// A log verifying under neither has been tampered with, and blessing it would erase
// the evidence.
func TestConvergeRefusesAnUnverifiableLog(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")
	mustLog(t, l, "admin.user_deleted")
	mustVerify(t, l, true, "before tampering")

	logPath := filepath.Join(root, "audit", logFile)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var entries []Entry
	for _, line := range splitLines(data) {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}

	// A digest belonging to no scheme: not the shared one, not either legacy one.
	entries[len(entries)-1].Details = "tampered"
	entries[len(entries)-1].Hash = strings.Repeat("ab", 32)

	var buf bytes.Buffer
	for _, e := range entries {
		b, _ := json.Marshal(e)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(logPath, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	tampered, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	// Reopening must not convert it. Refusing to open at all is an acceptable
	// outcome; quietly rewriting it is not.
	reopened, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
	if err == nil {
		mustVerify(t, reopened, false, "after tampering with an entry digest")
	}

	after, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tampered, after) {
		t.Fatal("conversion rewrote a log that verified under no known digest")
	}
}

// The one-ahead adoption is only safe because the extra record must carry a digest
// only a key holder can mint. A forged entry appended past the mark must be refused,
// not adopted.
func TestOverrunIsNotAdoptedWithoutTheKey(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted"} {
		mustLog(t, l, a)
	}
	entries, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}

	forged := Entry{
		ID:        "forged",
		Timestamp: time.Now().UTC(),
		Action:    "admin.user_deleted",
		PrevHash:  entries[len(entries)-1].Hash,
		Hash:      strings.Repeat("ab", 32),
	}
	data, _ := json.Marshal(forged)
	f, err := os.OpenFile(filepath.Join(root, "audit", logFile), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(append(data, '\n'))
	f.Close()

	if _, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), ""); !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Fatalf("NewLogger on a forged overrun: err=%v, want ErrBrokenChain", err)
	}
}

// A mark that cannot be written must not stop the chain from advancing: the record is
// already on disk, so a chain left behind would fork the log on the next append.
func TestUnwritableMarkDoesNotForkTheChain(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")

	configDir := filepath.Join(root, "config")
	if err := os.Chmod(configDir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(configDir, 0700)

	if _, err := l.Log(context.Background(), "auth.logout", "u", "d", "127.0.0.1", "x"); err == nil {
		t.Fatal("Log hid an unwritable audit mark")
	}
	if _, err := l.Log(context.Background(), "auth.logout", "u", "d", "127.0.0.1", "x"); err == nil {
		t.Fatal("Log hid an unwritable audit mark")
	}

	// The log must still be a single well-formed chain, just ahead of its mark.
	entries, err := l.readEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	records := make([]auditchain.Record, 0, len(entries))
	for i, e := range entries {
		records = append(records, recordOf(e, uint64(i+1)))
	}
	if err := auditchain.Verify(l.key, records, auditchain.Anchor{Count: 3, Hash: entries[2].Hash}); err != nil {
		t.Fatalf("log forked after the mark became unwritable: %v", err)
	}
}
