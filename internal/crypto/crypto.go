package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	ScryptN      = 32768
	ScryptR      = 8
	ScryptP      = 1
	ScryptKeyLen = 32
)

// GenerateRandomBytes returns n cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomHex returns a hex-encoded random string with n random bytes.
func GenerateRandomHex(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateRandomBase64URL returns a base64url-encoded random string.
func GenerateRandomBase64URL(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GeneratePIN generates a 6-digit numeric PIN for device pairing.
func GeneratePIN() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	num := (int(b[0])<<16 | int(b[1])<<8 | int(b[2])) % 1000000
	return fmt.Sprintf("%06d", num), nil
}

// GeneratePaperRecoveryKey generates a 24-character human-readable recovery key (e.g. XXXX-XXXX-XXXX-XXXX).
func GeneratePaperRecoveryKey() (string, error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Crockford-ish base32 (no 0, O, 1, I)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, v := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(charset[int(v)%len(charset)])
	}
	return sb.String(), nil
}

// HashPassword hashes a password or auth secret using scrypt.
func HashPassword(secret, saltHex string) (string, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", fmt.Errorf("invalid salt hex: %w", err)
	}

	dk, err := scrypt.Key([]byte(secret), salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
	if err != nil {
		return "", fmt.Errorf("scrypt derivation failed: %w", err)
	}

	return hex.EncodeToString(dk), nil
}

// VerifyPassword verifies a password against a stored scrypt hash.
func VerifyPassword(secret, saltHex, storedHashHex string) bool {
	computed, err := HashPassword(secret, saltHex)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHashHex)) == 1
}
