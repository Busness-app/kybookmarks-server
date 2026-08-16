package crypto

import (
	"strings"
	"testing"
)

func TestCryptoUtils(t *testing.T) {
	salt, err := GenerateRandomHex(16)
	if err != nil || len(salt) != 32 {
		t.Fatalf("failed to generate salt: %v", err)
	}

	pass := "super-secure-master-password-123"
	hash, err := HashPassword(pass, salt)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	if !VerifyPassword(pass, salt, hash) {
		t.Fatal("expected password verification to succeed")
	}

	if VerifyPassword("wrong-password", salt, hash) {
		t.Fatal("expected password verification to fail on wrong password")
	}

	pin, err := GeneratePIN()
	if err != nil || len(pin) != 6 {
		t.Fatalf("expected 6-digit pin, got %s", pin)
	}

	recoveryKey, err := GeneratePaperRecoveryKey()
	if err != nil || len(strings.ReplaceAll(recoveryKey, "-", "")) != 16 {
		t.Fatalf("expected formatted recovery key, got %s", recoveryKey)
	}
}
