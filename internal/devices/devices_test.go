package devices

import (
	"os"
	"testing"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

func TestDevicePairingFlow(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devices-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	s, err := store.NewStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dStore := NewStore(s)

	sess, err := dStore.RequestPairing("user-1", "MacBook Pro", "browser_chrome")
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.PIN) != 6 || len(sess.PairingToken) == 0 {
		t.Fatalf("invalid pairing session generated: %+v", sess)
	}

	// Try redeeming before approval (must fail with ErrNotApproved)
	_, err = dStore.RedeemPairing(sess.PairingToken, "client-pub-key")
	if err != ErrNotApproved {
		t.Fatalf("expected ErrNotApproved, got %v", err)
	}

	// Approve pairing with PIN and encrypted key envelope
	err = dStore.ApprovePairing(sess.PIN, "encrypted-vault-key-envelope-bytes")
	if err != nil {
		t.Fatalf("approval failed: %v", err)
	}

	// Redeem pairing
	redeemed, err := dStore.RedeemPairing(sess.PairingToken, "client-pub-key")
	if err != nil {
		t.Fatalf("redeem failed: %v", err)
	}
	if redeemed.VaultKeyEnvelope != "encrypted-vault-key-envelope-bytes" {
		t.Fatalf("unexpected vault key envelope: %s", redeemed.VaultKeyEnvelope)
	}

	// Double redemption should fail
	_, err = dStore.RedeemPairing(sess.PairingToken, "client-pub-key")
	if err != ErrAlreadyRedeemed {
		t.Fatalf("expected ErrAlreadyRedeemed, got %v", err)
	}
}
