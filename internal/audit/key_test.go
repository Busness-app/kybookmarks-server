package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/auditchain"
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

// Deleting the state file is tampering, not a fresh start, and the server refuses to
// start rather than running on without it.
//
// It used to start and report the log as invalid forever. That reads like a detector and
// is not one: with the mark gone there is nothing left to compare the log against, so the
// alarm is on whatever the log contains — a truncated log and an intact one produce the
// same output, which is asserted below. Refusing is also what this server already does for
// a log emptied, junk-filled or deleted, and a missing mark is worse than any of them
// because it is what disarms those checks.
func TestMissingStateIsNotSelfHealed(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
		mustLog(t, l, a)
	}
	statePath := filepath.Join(root, "config", stateFile)
	logPath := filepath.Join(root, "audit", logFile)
	intact, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}

	// Repeatable: restarting does not talk the logger into accepting it. The message has
	// to name the mark and give the operator both ways out, because Resume also refuses a
	// log it cannot place — with an error about digests that says nothing about which file
	// is missing or what to do about it. Reaching that refusal instead of this one is a
	// regression even though both stop the boot.
	for _, why := range []string{"first restart", "second restart"} {
		_, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
		if !errors.Is(err, auditchain.ErrBrokenChain) {
			t.Fatalf("%s with the mark deleted: err=%v, want ErrBrokenChain", why, err)
		}
		for _, want := range []string{
			statePath,
			"counts none",
			"Restore the mark",
			"move both files aside",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%s: the refusal does not mention %q, so it is not the missing-mark answer: %v", why, want, err)
			}
		}
	}

	// And the mark is not recreated by the attempt, which would bless whatever is on disk.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("a failed start recreated the deleted audit state (err=%v)", err)
	}

	// The reason it must refuse: with the mark gone, truncating the log changes nothing
	// about the answer. Any response other than refusal is content-free.
	lines := splitLines(intact)
	if err := os.WriteFile(logPath, []byte(string(lines[0])+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, truncErr := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
	if truncErr == nil {
		t.Fatal("a truncated log with no mark was accepted")
	}

	// Restoring the mark restores the distinction, which is the whole point of keeping it
	// outside dataDir.
	if err := os.WriteFile(logPath, intact, 0600); err != nil {
		t.Fatal(err)
	}
	restored, _ := json.Marshal(state{Count: 3, Hash: readTailHash(t, logPath)})
	if err := os.WriteFile(statePath, restored, 0600); err != nil {
		t.Fatal(err)
	}
	recovered := newTestLogger(t, root)
	mustVerify(t, recovered, true, "mark restored from backup")
}

// readTailHash returns the Hash of the last entry in the log at path.
func readTailHash(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(data)
	var e Entry
	if err := json.Unmarshal(lines[len(lines)-1], &e); err != nil {
		t.Fatal(err)
	}
	return e.Hash
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
	logPath := filepath.Join(root, "audit", logFile)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// Checked, because a setup write that half-lands makes this a test of something
	// else: the forged record would not be in the log and NewLogger would refuse, or
	// not, for reasons that have nothing to do with the key.
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if after, err := l.ReadEntries(0); err != nil {
		t.Fatal(err)
	} else if len(after) != len(entries)+1 || after[len(after)-1].ID != "forged" {
		t.Fatalf("setup did not append the forged record: log holds %d records", len(after))
	}

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

	for i := 0; i < 2; i++ {
		_, err := l.Log(context.Background(), "auth.logout", "u", "d", "127.0.0.1", "x")
		if err == nil {
			t.Fatal("Log hid an unwritable audit mark")
		}
		// The record is on disk; the error has to say so, or the caller reports it missing.
		if !errors.Is(err, ErrMarkNotAdvanced) {
			t.Fatalf("Log returned %v, want ErrMarkNotAdvanced", err)
		}
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

// writeLog replaces the log file with exactly these entries, one JSON object per line.
func writeLog(t *testing.T, root string, entries []Entry) {
	t.Helper()
	var buf strings.Builder
	for _, e := range entries {
		b, _ := json.Marshal(e)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(root, "audit", logFile), []byte(buf.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

// A config volume that was unwritable for a while leaves the mark several records
// behind, not one. That is a disk fault, not tampering: once the volume is writable the
// next start must verify the whole run and catch up, rather than refuse to boot.
func TestMarkManyBehindIsCaughtUp(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")

	configDir := filepath.Join(root, "config")
	if err := os.Chmod(configDir, 0500); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Log(context.Background(), "auth.logout", "u", "d", "127.0.0.1", "x"); err == nil {
			t.Fatal("Log hid an unwritable audit mark")
		}
	}
	if err := os.Chmod(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	restarted := newTestLogger(t, root)
	mustVerify(t, restarted, true, "restart with the mark three behind")
	st, err := restarted.loadState()
	if err != nil || st == nil {
		t.Fatalf("loadState: %v", err)
	}
	if st.Count != 4 {
		t.Fatalf("mark caught up to %d, want 4", st.Count)
	}
}

// Every record past the mark must follow the one before it, not merely carry a valid
// digest for its own position. A fork spliced in past the mark verifies record by record
// and is caught only by the predecessor check.
func TestOverrunRunMustChain(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
		mustLog(t, l, a)
	}
	entries, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}

	// Re-mint the second entry with different content and rebuild the third on top of
	// that fork. The third then carries a real digest for sequence 3 while pointing at a
	// predecessor the log does not contain.
	forked := entries[1]
	forked.Details = "different"
	records, _, err := auditchain.Replay(l.key, [][]string{
		fieldsOf(entries[0]), fieldsOf(forked), fieldsOf(entries[2]),
	})
	if err != nil {
		t.Fatal(err)
	}
	entries[2].PrevHash, entries[2].Hash = records[2].Prev, records[2].Hash
	writeLog(t, root, entries)

	// Mark at one, so entries two and three are the overrun run.
	st, _ := json.Marshal(state{Count: 1, Hash: entries[0].Hash})
	if err := os.WriteFile(filepath.Join(root, "config", stateFile), st, 0600); err != nil {
		t.Fatal(err)
	}

	if auditchain.VerifyRecord(l.key, recordOf(entries[2], 3)) != nil {
		t.Fatal("test is not exercising the predecessor check: the spliced record fails VerifyRecord")
	}
	if _, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), ""); !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Fatalf("NewLogger on a spliced overrun: err=%v, want ErrBrokenChain", err)
	}
}

// appendTimeout is a real bound only because acquire never contends: Log holds l.mu
// across the whole Append, and l.chain is used from exactly one place in the package.
// A second call site would put a waiter behind a hung store with no way to shed, and
// the deadline would start firing on a queue instead of on a fault.
func TestChainIsDrivenFromOneCallSite(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	var sites []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", f, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, ".chain.") {
				sites = append(sites, fmt.Sprintf("%s:%d", f, i+1))
			}
		}
	}
	if len(sites) != 1 {
		t.Fatalf("the chain is driven from %d places %v; appendTimeout is only a bound while there is one", len(sites), sites)
	}
}

// definedTests collects every test function the repository actually defines.
//
// The pattern is anchored to the start of a line. A Go test function can only be declared
// at column zero, and without the anchor a commented-out "// func TestX(" was a definition
// as far as this map was concerned -- so a comment citing a test that had been written,
// deleted and left behind as a comment satisfied the guard that exists precisely to catch
// that. TestCommentedOutDefinitionDoesNotCount holds it.
func definedTests(t *testing.T) map[string]bool {
	t.Helper()
	decl := regexp.MustCompile(`(?m)^func (Test[A-Z]\w*)\(`)
	defined := map[string]bool{}
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range decl.FindAllStringSubmatch(string(data), -1) {
			defined[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}
	return defined
}

// The fixture for the test below, and the thing the guard used to accept: a definition
// that is not one.
//
// func TestSomethingThatDoesNotExist(t *testing.T) {}
//
// It sits in a test file because TestCommentsNameRealTests reads comments in non-test
// sources only; here it is a fixture, there it would be a citation.
func TestCommentedOutDefinitionDoesNotCount(t *testing.T) {
	const commented = "TestSomethingThatDoesNotExist"
	if definedTests(t)[commented] {
		t.Fatalf("a commented-out func %s( counted as a definition, so a comment citing it would pass the guard", commented)
	}
}

// A comment naming a test it is not backed by is worse than no comment: it reads as
// evidence. Every Test... identifier mentioned in a non-test source file anywhere in the
// repository must name a test that exists.
//
// "Anywhere" is the second half of the fix: this globbed internal/audit alone, so the
// citations in internal/api -- the ones backing the claims about the audit-failure path
// and the health endpoint -- were outside the guard that exists for exactly them.
func TestCommentsNameRealTests(t *testing.T) {
	defined := definedTests(t)
	name := regexp.MustCompile(`\bTest[A-Z]\w*`)
	var cited []string

	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, n := range name.FindAllString(line, -1) {
				if !defined[n] {
					cited = append(cited, fmt.Sprintf("%s:%d cites %s", path, i+1, n))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}
	if len(cited) > 0 {
		t.Fatalf("comments name tests that do not exist: %v", cited)
	}
}

// A hung store must delay the next record, never discard it. persist runs with the chain
// lock held and no context reaches it, so appendTimeout cannot bound the caller that is
// stuck -- but the caller queued behind it on l.mu must still get its full budget once it
// can make progress. Deriving the deadline above the mutex spent it on the wait, and the
// queued record was thrown away: the same suppression a dropped connection used to buy,
// reached by load instead, which is what a brute-forcer generates.
func TestHungStoreDelaysTheNextRecordButNeverDropsIt(t *testing.T) {
	if testing.Short() {
		t.Skip("holds a real FIFO open for longer than appendTimeout")
	}
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")

	// Replace the log with a FIFO nobody is reading: os.OpenFile then blocks in the
	// kernel, inside persist, where no context can reach it.
	logPath := filepath.Join(root, "audit", logFile)
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(logPath, 0600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	first := make(chan error, 1)
	go func() {
		_, err := l.Log(context.Background(), "auth.logout", "u", "d", "127.0.0.1", "first")
		first <- err
	}()

	// Wait until the first caller owns l.mu, so the second is genuinely the queued one.
	for deadline := time.Now().Add(10 * time.Second); l.mu.TryLock(); {
		l.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("first Log never took the audit mutex")
		}
		runtime.Gosched()
	}

	second := make(chan error, 1)
	go func() {
		_, err := l.Log(context.Background(), "auth.logout", "u", "d", "127.0.0.1", "second")
		second <- err
	}()

	// The hang has to outlast appendTimeout: that is the whole experiment, so the wait
	// is the measurement rather than a guess at how long something takes.
	time.Sleep(appendTimeout + time.Second)

	// O_RDWR so the reader never sees EOF in the gap between the two writers.
	r, err := os.OpenFile(logPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	lines := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()

	if err := <-first; err != nil {
		t.Fatalf("first Log: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("a hung store discarded the queued record instead of delaying it: %v", err)
	}

	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case ln := <-lines:
			for _, want := range []string{"first", "second"} {
				if strings.Contains(ln, `"details":"`+want+`"`) {
					seen[want] = true
				}
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out reading records back from the pipe, saw %v", seen)
		}
	}
	if !seen["first"] || !seen["second"] {
		t.Fatalf("pipe held %v, want both records", seen)
	}
}

// A log emptied to zero bytes, filled with junk, or deleted outright reads as no entries
// at all. That is the most truncated a log can be, and it must not get a gentler answer
// than a log truncated to one record: before the check was hoisted above the empty-log
// short-circuit, the worst case opened and accepted appends.
//
// All three are refused. Junk is refused as damage rather than as removal, because that
// is what it is; the answer is the same boot failure either way.
func TestEmptyOrCorruptLogWithAMarkIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name     string
		want     error
		mutilate func(t *testing.T, logPath string)
	}{
		{"zero bytes", auditchain.ErrTruncated, func(t *testing.T, p string) {
			if err := os.WriteFile(p, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"not json", ErrCorruptLog, func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("not json at all\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"deleted", auditchain.ErrTruncated, func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			l := newTestLogger(t, root)
			for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
				mustLog(t, l, a)
			}
			tc.mutilate(t, filepath.Join(root, "audit", logFile))

			_, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
			if !errors.Is(err, tc.want) {
				t.Fatalf("NewLogger on a %s log with a mark of 3: err=%v, want %v", tc.name, err, tc.want)
			}
		})
	}
}

// converge re-mints a legacy log under the real key. Deciding to do that on the log's
// own contents alone hands an attacker with write access to dataDir a laundering
// service: legacyDefaultSecret is published in this repository, so anyone can author a
// chain that verifies under it, and converge used to accept any such chain whenever the
// mark was present but merely counted no more entries than the log held.
//
// The real records are replaced by attacker-authored ones, the next boot re-mints them
// under the real HMAC key, VerifyChain returns true, and the mark is overwritten to
// match. The forgery is then indistinguishable from a genuine log.
//
// The mark is the only thing outside the attacker's reach, so it is what converge must
// consult: both the count and the tail hash.
func TestForgedLegacyLogIsNotLaunderedByConverge(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "audit")
	configDir := filepath.Join(root, "config")

	// A real chain, written by the real logger under its real key.
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
		mustLog(t, l, a)
	}
	real, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(real) != 3 {
		t.Fatalf("setup wrote %d records, want 3", len(real))
	}

	// The attacker reaches dataDir only. The key and the mark are in configDir and are
	// never read or written here.
	forger := &Logger{legacyKey: []byte(legacyDefaultSecret)}
	prev := genesisHash
	var buf bytes.Buffer
	var forged []Entry
	for i, a := range []string{"auth.login", "admin.user_created", "auth.logout"} {
		e := Entry{
			ID:        "forged-" + a,
			Timestamp: time.Unix(int64(1800000000+i), 0).UTC(),
			Action:    a,
			UserID:    "attacker",
			PrevHash:  prev,
		}
		e.Hash = forger.legacyHash(e, version0)
		prev = e.Hash
		b, _ := json.Marshal(e)
		buf.Write(b)
		buf.WriteByte('\n')
		forged = append(forged, e)
	}
	if err := os.WriteFile(filepath.Join(dataDir, logFile), buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

	// Same record count as the real log, so a count-only check cannot see this.
	if len(forged) != len(real) {
		t.Fatalf("the exploit needs an equal-length substitution, got %d for %d", len(forged), len(real))
	}
	before, err := os.ReadFile(filepath.Join(configDir, stateFile))
	if err != nil {
		t.Fatal(err)
	}

	// The next boot must not bless this. Either it refuses outright, or it starts and
	// reports the log as invalid — what it must never do is re-mint the forged records
	// under the real key and then say they verify.
	restarted, err := NewLogger(dataDir, configDir, "")
	if err == nil {
		mustVerify(t, restarted, false, "log replaced with one chained under the published constant")

		entries, rerr := restarted.ReadEntries(0)
		if rerr != nil {
			t.Fatal(rerr)
		}
		// Each record against its own position. Against a constant sequence 1 the check
		// was vacuous for every record but the first: a re-minted record 2 carries the
		// digest for sequence 2, which never matches the digest for sequence 1, so a
		// laundering that spared the first record passed unnoticed.
		for i, e := range entries {
			if auditchain.VerifyRecord(restarted.key, recordOf(e, uint64(i+1))) == nil && strings.HasPrefix(e.ID, "forged-") {
				t.Fatalf("forged record %d now carries a digest under the real audit key", i+1)
			}
		}
	}

	after, err := os.ReadFile(filepath.Join(configDir, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("the mark was overwritten to match the forged log:\nbefore %s\nafter  %s", before, after)
	}
}

// converge must consult the mark *and* the digests. The mark says how long the log is and
// what its tail is; it says nothing about the entries in between, so a log whose middle
// has been rewritten still matches a mark that names its count and tail. legacyVersions is
// what refuses that, and it has to keep doing so even when the mark agrees.
func TestConvergeRefusesAMarkedLogThatVerifiesUnderNeitherDigest(t *testing.T) {
	root := t.TempDir()
	legacy := writeLegacyLog(t, root, "auth.login", "admin.user_deleted", "auth.logout")

	// Rewrite the content of a middle entry and leave every hash alone. The links still
	// join up and the tail is untouched, so the mark below names this file exactly.
	legacy[1].Details = "tampered"
	var buf bytes.Buffer
	for _, e := range legacy {
		b, _ := json.Marshal(e)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	logPath := filepath.Join(root, "audit", logFile)
	if err := os.WriteFile(logPath, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	tampered, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	// A mark that agrees with the log on both facts it records.
	if err := os.MkdirAll(filepath.Join(root, "config"), 0700); err != nil {
		t.Fatal(err)
	}
	mark, _ := json.Marshal(state{Count: len(legacy), Hash: legacy[len(legacy)-1].Hash})
	if err := os.WriteFile(filepath.Join(root, "config", stateFile), mark, 0600); err != nil {
		t.Fatal(err)
	}

	// Converting this would re-mint a tampered entry under the real audit key. Refusing
	// to open is fine; rewriting the log is not.
	reopened, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
	if err == nil {
		mustVerify(t, reopened, false, "a marked log with a rewritten middle entry")
	}
	after, rerr := os.ReadFile(logPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !bytes.Equal(tampered, after) {
		t.Fatal("the log was converted even though an entry verifies under neither digest")
	}
}

// A record and its terminator go out in one Write, but a short write on a full disk, or
// a crash, leaves the file ending mid-record. The next successful append used to be
// welded onto that fragment, producing one line that decodes as neither record: the entry
// that landed was lost, the parsed count sat one below the mark forever, and every
// subsequent boot died with ErrTruncated telling the operator entries had been removed
// from the end of the log. Power loss is enough to reach it, and nothing short of editing
// the log by hand got the server started again.
func TestTornWriteDoesNotMergeIntoTheNextRecord(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
		mustLog(t, l, a)
	}

	// A torn write: the record's bytes land, the terminating newline does not. The chain
	// did not advance and the mark was not saved, so this state alone is harmless.
	logPath := filepath.Join(root, "audit", logFile)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"id":"torn","action":"admin.user`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// The running logger cannot have seen it, so it has to cope the way a fresh one does.
	restarted := newTestLogger(t, root)

	// The next successful append is where the damage used to happen.
	want := mustLog(t, restarted, "auth.login")

	entries, err := restarted.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("log parses to %d records, want 4: the append merged into the fragment", len(entries))
	}
	if entries[3].Hash != want.Hash {
		t.Fatalf("the record that followed the fragment is not the one Log wrote")
	}
	mustVerify(t, restarted, true, "an append after a torn write")

	// And the server still starts, because the fragment changed no record count.
	again, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
	if err != nil {
		t.Fatalf("a torn write became a boot failure: %v", err)
	}
	mustVerify(t, again, true, "restart after a torn write")
}

// A short log with undecodable lines and a short log without them are different files,
// and the message must describe the one it read. Both used to come back as ErrTruncated
// -- "entries have been removed from the end of the log" -- which states a cause this
// package cannot establish: a power cut produces the first file, and so does an attacker
// who shortens the log and drops in a junk line. This pins which error each shape
// returns, and nothing more. Both refuse to boot.
func TestCorruptLineIsNotReportedAsTruncation(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
		mustLog(t, l, a)
	}
	entries, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the middle record's line rather than removing it: the file still holds
	// three lines, but only two of them decode.
	var buf bytes.Buffer
	for i, e := range entries {
		if i == 1 {
			buf.WriteString("{\"id\":\"half-a-rec\n")
			continue
		}
		b, _ := json.Marshal(e)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(root, "audit", logFile), buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

	_, err = NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
	if !errors.Is(err, ErrCorruptLog) {
		t.Fatalf("NewLogger on a log with a corrupt line: err=%v, want ErrCorruptLog", err)
	}
	if errors.Is(err, auditchain.ErrTruncated) {
		t.Fatalf("damage was reported as records removed from the end: %v", err)
	}

	// Removal, by contrast, is still truncation.
	var kept bytes.Buffer
	for _, e := range entries[:2] {
		b, _ := json.Marshal(e)
		kept.Write(b)
		kept.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(root, "audit", logFile), kept.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
	if !errors.Is(err, auditchain.ErrTruncated) {
		t.Fatalf("NewLogger on a shortened log: err=%v, want ErrTruncated", err)
	}
}

// Every record past the mark must carry its own digest, not merely link to its
// neighbours. Resume already refuses a bad digest on the *tail*, so a forged record
// appended at the end is caught whether or not recover() checks the run -- which left the
// per-record check in the overrun branch doing nothing any test could see. Tamper with a
// record in the middle of the run instead, leaving every hash field alone so the links
// still join and the tail is genuine: only the per-record check can see it.
func TestOverrunRecordsMustCarryTheirOwnDigest(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout", "auth.login"} {
		mustLog(t, l, a)
	}
	entries, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite record 3's content and leave its digest and both links untouched.
	entries[2].Details = "tampered"
	writeLog(t, root, entries)

	// Mark at one, so records two through four are the overrun run and record four --
	// the tail Resume checks -- is untouched and genuine.
	st, _ := json.Marshal(state{Count: 1, Hash: entries[0].Hash})
	if err := os.WriteFile(filepath.Join(root, "config", stateFile), st, 0600); err != nil {
		t.Fatal(err)
	}
	if auditchain.VerifyRecord(l.key, recordOf(entries[3], 4)) != nil {
		t.Fatal("test is not isolating the per-record check: the tail no longer verifies")
	}
	if recordOf(entries[2], 3).Prev != entries[1].Hash || entries[3].PrevHash != entries[2].Hash {
		t.Fatal("test is not isolating the per-record check: the predecessor links no longer join")
	}

	if _, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), ""); !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Fatalf("NewLogger on an overrun holding a tampered record: err=%v, want ErrBrokenChain", err)
	}
}

// A write can fail *after* the complete record and its terminator are already on disk.
// Write reports the bytes it handed to the kernel; the failure surfaces from Close, as a
// deferred write-back error -- EIO, ENOSPC or EDQUOT on a network- or FUSE-backed volume,
// and a DATA_DIR bind mount can be either. persist returns that error, so the chain does
// not advance, while the log has grown by one record.
//
// Treating every failed write as a fragment is wrong for exactly that case: the next Log
// mints the same sequence again and appends it one line further down, so from there every
// entry sits one position past the sequence its digest was minted for. VerifyChain fails
// immediately and the next start refuses with ErrBrokenChain -- the same permanent,
// tampering-flavoured boot failure the short-write fix removed, reached through the other
// branch of the same if.
//
// No portable syscall makes Close fail after a complete write, so the on-disk state is
// reproduced directly: it is the only thing the two branches differ by, and it is what the
// next write has to decide from.
func TestFailedWriteReconcilesAgainstTheLog(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")
	mustLog(t, l, "admin.user_deleted")

	// Mint record 3 the way persist would -- from this Logger's own key and anchor --
	// without telling this Logger's chain, which stays at 2.
	entry := Entry{
		ID:        "9f3c1d6e-0000-4000-8000-000000000003",
		Timestamp: time.Now().UTC(),
		Action:    "auth.logout",
		UserID:    "user-1",
		DeviceID:  "device-1",
		IP:        "127.0.0.1",
		Details:   "the record whose Close failed",
	}
	tail, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	shadow, err := auditchain.Resume(l.key, recordOf(tail[len(tail)-1], uint64(len(tail))), l.anchor)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	rec, err := shadow.Append(t.Context(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fieldsOf(entry)...)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	entry.PrevHash, entry.Hash = rec.Prev, rec.Hash
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}

	// The complete record and its newline land, and then the write fails.
	logPath := filepath.Join(root, "audit", logFile)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// The other half of what that failure leaves behind: Log returned an error, so the
	// chain was invalidated. It is set here rather than driven, because no portable
	// syscall makes Close fail after a complete write; TestShortWriteLeavesATornTail
	// drives a real failed write and pins that the error path sets this.
	l.stale = true

	// One Log on the still-running Logger. It has to reconcile against the file rather
	// than mint sequence 3 a second time.
	mustLog(t, l, "bookmark.create")

	entries, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("log parses to %d records, want 4", len(entries))
	}
	restarted, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
	if err != nil {
		t.Fatalf("a failed write became a boot failure: %v", err)
	}
	mustVerify(t, restarted, true, "restart after a write that failed with the record on disk")
	mustVerify(t, l, true, "an append after a write that failed with the record on disk")
}
