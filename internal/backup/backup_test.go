package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

func TestSettingsAdapterMapsNotFound(t *testing.T) {
	st, err := store.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := Settings(st)
	if _, err := s.Get("nope"); !errors.Is(err, recoveryclient.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	_ = s.Set("a", "1")
	if v, _ := s.Get("a"); v != "1" {
		t.Fatal("set/get")
	}
	if err := s.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a"); !errors.Is(err, recoveryclient.ErrNotFound) {
		t.Fatal("delete")
	}
}

func TestSealerRoundTrip(t *testing.T) {
	s, err := NewSealer(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := s.Seal([]byte("tok"))
	p, err := s.Open(c)
	if err != nil || string(p) != "tok" {
		t.Fatal(err)
	}
}

func TestAuditDetailsIsStableAndBounded(t *testing.T) {
	got := AuditDetails(map[string]any{"b": 2, "a": "x"})
	if got != "a=x b=2" {
		t.Fatalf("%q", got)
	}
	// The lib cuts at 200 printable characters and appends an ellipsis.
	if len(AuditDetails(map[string]any{"k": strings.Repeat("z", 1000)})) > 203 {
		t.Fatal("unbounded")
	}
}

// The ciphertext and pin were produced before the module bump, not by the code under test.
func TestV050PairingStillOpens(t *testing.T) {
	raw, err := os.ReadFile("testdata/pairing-v050.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Settings  map[string]string `json:"settings"`
		PublicKey []byte            `json:"public_key"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	st, dataDir, _ := seed(t)
	for k, v := range fixture.Settings {
		if err := st.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(recoveryclient.RecoveryKeyPath(dataDir), fixture.PublicKey, 0600); err != nil {
		t.Fatal(err)
	}
	sealer, err := NewSealer(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pairing, err := recoveryclient.LoadPairing(dataDir, Settings(st), sealer)
	if err != nil {
		t.Fatal(err)
	}
	if pairing.Token != "synthetic-v050-token" || pairing.URL != "https://recovery.example.com" || pairing.Key.Public.ID() != fixture.Settings["kyrecovery_key_id"] || pairing.Key.Threshold != 2 || pairing.Key.TotalShares != 3 {
		t.Fatal("pairing identity changed")
	}
	for _, tc := range []struct {
		key   []byte
		label string
	}{{bytes.Repeat([]byte{2}, 32), tokenLabel}, {bytes.Repeat([]byte{1}, 32), "another-product"}} {
		wrong, err := recoveryclient.NewAESGCMSealer(tc.key, tc.label)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := recoveryclient.LoadPairing(dataDir, Settings(st), wrong); err == nil {
			t.Fatal("pairing opened with wrong key/label")
		}
	}
}
