package crypto

import (
	"strings"
	"testing"
)

func TestPasswordHashIsArgon2idAndVerifies(t *testing.T) {
	pass := "super-secure-master-password-123"
	hash, err := HashPassword(pass)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash is not PHC argon2id: %q", hash)
	}
	if !VerifyPassword(pass, hash) {
		t.Fatal("expected password verification to succeed")
	}
	if VerifyPassword("wrong-password", hash) {
		t.Fatal("expected password verification to fail on wrong password")
	}
	if VerifyPassword(pass, "not-a-hash") {
		t.Fatal("a malformed stored hash must verify false, never true")
	}
	pin, err := GeneratePIN()
	if err != nil || len(pin) != 6 {
		t.Fatalf("expected 6-digit pin, got %s", pin)
	}
}
