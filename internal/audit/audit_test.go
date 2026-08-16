package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLogAndVerify(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logger, err := NewLogger(tmpDir, "test-secret")
	if err != nil {
		t.Fatal(err)
	}

	_, err = logger.Log("auth.login", "user-1", "device-1", "127.0.0.1", "signed in")
	if err != nil {
		t.Fatal(err)
	}

	_, err = logger.Log("bookmark.create", "user-1", "device-1", "127.0.0.1", "new bookmark")
	if err != nil {
		t.Fatal(err)
	}

	valid, count, err := logger.VerifyChain()
	if err != nil || !valid || count != 2 {
		t.Fatalf("expected valid chain with 2 entries, got valid=%v, count=%d, err=%v", valid, count, err)
	}

	// Test recovery after restart
	logger2, err := NewLogger(tmpDir, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = logger2.Log("bookmark.sync", "user-1", "device-1", "127.0.0.1", "synced")
	if err != nil {
		t.Fatal(err)
	}

	valid, count, err = logger2.VerifyChain()
	if err != nil || !valid || count != 3 {
		t.Fatalf("expected valid chain with 3 entries after recovery, got valid=%v, count=%d, err=%v", valid, count, err)
	}

	// Tamper test
	logPath := filepath.Join(tmpDir, "audit.log")
	data, _ := os.ReadFile(logPath)
	data[len(data)-10] ^= 0xFF // corrupt byte
	_ = os.WriteFile(logPath, data, 0600)

	valid, _, _ = logger2.VerifyChain()
	if valid {
		t.Fatal("expected chain verification to fail after tampering")
	}
}
