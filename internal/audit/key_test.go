package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	e, err := l.Log(action, "user-1", "device-1", "127.0.0.1", "detail")
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
		entries[i].Hash = forger.computeHash(entries[i])
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

// A truncated log must not be repaired by restarting, and appends must not lower the mark.
func TestTruncationSurvivesRestartAndAppend(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	for _, a := range []string{"auth.login", "admin.user_deleted", "auth.logout"} {
		mustLog(t, l, a)
	}

	logPath := filepath.Join(root, "audit", logFile)
	data, _ := os.ReadFile(logPath)
	lines := splitLines(data)
	_ = os.WriteFile(logPath, []byte(string(lines[0])+"\n"), 0600)

	restarted := newTestLogger(t, root)
	mustVerify(t, restarted, false, "truncated log after restart")

	mustLog(t, restarted, "auth.login")
	mustVerify(t, restarted, false, "truncated log after a further append")
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

	stale := newTestLogger(t, root)
	stale.count = 1
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
		e.Hash = legacy.computeHash(e)
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

// Existing logs keep verifying, and a keyed marker anchors their tail so they cannot
// be rewritten after the upgrade.
func TestLegacyLogIsPreservedAndAnchored(t *testing.T) {
	root := t.TempDir()
	legacy := writeLegacyLog(t, root, "auth.login", "admin.user_deleted")

	l := newTestLogger(t, root)
	mustVerify(t, l, true, "after migration")

	entries, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(legacy)+1 {
		t.Fatalf("got %d entries after migration, want %d", len(entries), len(legacy)+1)
	}
	marker := entries[len(entries)-1]
	if marker.Action != actionRekeyed {
		t.Fatalf("last entry is %q, want %q", marker.Action, actionRekeyed)
	}
	if marker.V != version1 {
		t.Fatalf("marker version %d, want %d", marker.V, version1)
	}
	if marker.PrevHash != legacy[len(legacy)-1].Hash {
		t.Fatal("marker does not anchor the legacy tail")
	}

	// Restarting must not append a second marker.
	restarted := newTestLogger(t, root)
	again, _ := restarted.ReadEntries(0)
	if len(again) != len(entries) {
		t.Fatalf("restart appended %d extra entries", len(again)-len(entries))
	}
	mustVerify(t, restarted, true, "after restart")

	// Rewriting a legacy record with the published key must now break the marker.
	forger := &Logger{legacyKey: []byte(legacyDefaultSecret)}
	tampered := legacy[1]
	tampered.Action = "auth.login"
	tampered.Hash = forger.computeHash(tampered)
	b, _ := json.Marshal(tampered)
	first, _ := json.Marshal(legacy[0])
	markerJSON, _ := json.Marshal(marker)
	out := string(first) + "\n" + string(b) + "\n" + string(markerJSON) + "\n"
	if err := os.WriteFile(filepath.Join(root, "audit", logFile), []byte(out), 0600); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, restarted, false, "legacy record rewritten under the published key")
}

func TestAuditKeyEnvMustBeStrong(t *testing.T) {
	root := t.TempDir()
	t.Setenv(keyEnv, "hunter2")
	if _, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), ""); err == nil {
		t.Fatal("NewLogger accepted a short AUDIT_KEY")
	}
}
