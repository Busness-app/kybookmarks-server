package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/Busness-app/ky-primitives/password"
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

// HashPassword returns a PHC-encoded Argon2id hash at the suite parameters
// (RFC 9106 second profile). The hash carries its own salt and cost.
func HashPassword(secret string) (string, error) {
	return password.Hash(secret)
}

// VerifyPassword compares in constant time. A malformed stored hash, or a
// derivation shed under memory pressure, is false, never a panic.
func VerifyPassword(secret, encoded string) bool {
	ok, err := password.Verify(secret, encoded)
	return err == nil && ok
}
