package backup

import (
	"bytes"
	"errors"
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
