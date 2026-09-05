package store

import (
	"errors"
	"testing"
)

func TestSettingsRoundTripAndNotFound(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetSetting("never"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.SetSetting("k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("k", "v2"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GetSetting("k"); v != "v2" {
		t.Fatalf("got %q", v)
	}
	if err := s.DeleteSetting("k"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSetting("k"); err != nil {
		t.Fatalf("second delete must be idempotent: %v", err)
	}
	if _, err := s.GetSetting("k"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted key still readable")
	}
}
