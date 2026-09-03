package audit

import (
	"bytes"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
)

// A full disk does not fail cleanly: the kernel writes what fits and reports a short
// write, so the log ends mid-record. persist records that on the Logger it is running
// on, and until this test nothing exercised that assignment — every torn-tail test tore
// the file behind the Logger's back and then restarted it, so the fragment was found by
// scanLog and the in-process path was never taken. Deleting the assignment left the whole
// suite green while a live server welded its next record onto the fragment.
//
// RLIMIT_FSIZE produces the short write without a full disk. It is process-wide, so it is
// lowered for one call and put straight back, and SIGXFSZ — which the kernel raises
// alongside the failure and which would otherwise kill the test binary — is ignored for
// the duration.
func TestShortWriteLeavesATornTail(t *testing.T) {
	root := t.TempDir()
	l := newTestLogger(t, root)
	mustLog(t, l, "auth.login")
	mustLog(t, l, "admin.user_deleted")

	logPath := filepath.Join(root, "audit", logFile)
	before, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	// Room for a fraction of the next record, so the write is short rather than refused.
	capped := syscall.Rlimit{Cur: uint64(len(before)) + 20, Max: old.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &capped); err != nil {
		t.Skipf("cannot lower RLIMIT_FSIZE here: %v", err)
	}
	_, logErr := l.Log(t.Context(), "auth.logout", "user-1", "device-1", "127.0.0.1", "the record that does not fit")
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("Setrlimit restore: %v", err)
	}

	if logErr == nil {
		t.Fatal("Log reported success for a record that could not be written")
	}
	// A real failed write invalidates the chain, because what landed is not knowable
	// from inside persist. TestFailedWriteReconcilesAgainstTheLog leans on this.
	if !l.stale {
		t.Fatal("a failed write left the chain describing a log it no longer matches")
	}
	torn, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(torn) <= len(before) || torn[len(torn)-1] == '\n' {
		t.Skipf("the capped write landed no fragment (%d bytes before, %d after)", len(before), len(torn))
	}

	// The same Logger, still running, takes the next record. This is the case the
	// in-process assignment exists for: nothing has re-scanned the file.
	want := mustLog(t, l, "auth.login")

	entries, err := l.ReadEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("log parses to %d records, want 3: the append merged into the fragment", len(entries))
	}
	if entries[2].Hash != want.Hash {
		t.Fatal("the record written after the short write is not the one Log returned")
	}
	if !bytes.HasPrefix(torn, before) {
		t.Fatal("the short write rewrote bytes that were already on disk")
	}
	mustVerify(t, l, true, "an append after a short write")

	// And the server still starts: the fragment is a line of its own, so it changes no
	// record count.
	restarted, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), "")
	if err != nil {
		t.Fatalf("a short write became a boot failure: %v", err)
	}
	mustVerify(t, restarted, true, "restart after a short write")
}
