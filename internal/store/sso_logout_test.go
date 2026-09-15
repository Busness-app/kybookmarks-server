package store

import (
	"errors"
	"testing"
	"time"
)

func TestSSOLogoutReplayAndFenceSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ev := SSOLogoutEvent{Issuer: "https://idp", ClientID: "c", JTI: "j1", Subject: "u1", IssuedAt: time.Now().Unix()}
	if _, err := s.ApplySSOLogout(ev, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.ApplySSOLogout(ev, time.Now().UTC().Add(time.Hour)); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("replay after restart: %v, want ErrAlreadyExists", err)
	}
	acc := &Account{Username: "u1", Email: "u1@example.com", AuthSalt: "0", SSOSubject: "u1"}
	if err := s.CreateAccount(acc); err != nil {
		t.Fatal(err)
	}
	fenced := &Session{TokenHash: "h1", UserID: acc.ID, CSRFToken: "c", ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
		SSOIssuer: "https://idp", SSOClientID: "c", SSOSubject: "u1", SSOSID: "s1", SSOIssuedAt: ev.IssuedAt}
	if err := s.CreateSession(fenced); !errors.Is(err, ErrSSOLoggedOut) {
		t.Fatalf("fence after restart: %v, want ErrSSOLoggedOut", err)
	}
	later := *fenced
	later.TokenHash, later.SSOIssuedAt = "h2", ev.IssuedAt+1
	if err := s.CreateSession(&later); err != nil {
		t.Fatalf("login after the logout: %v", err)
	}
}

// Sessions from before the identity columns existed cannot be matched by any logout, so
// adding the columns ends the sessions of SSO-linked accounts once. Local accounts keep theirs.
func TestSSOMigrationEndsUnmatchableSessionsOnce(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the pre-migration table shape.
	for _, q := range []string{
		`DROP TABLE sessions`,
		`CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
			device_id TEXT, csrf_token TEXT NOT NULL, expires_at DATETIME NOT NULL, created_at DATETIME NOT NULL)`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	linked := &Account{Username: "sso", Email: "sso@example.com", AuthSalt: "0", SSOSubject: "sub"}
	local := &Account{Username: "local", Email: "local@example.com", AuthSalt: "0"}
	for _, a := range []*Account{linked, local} {
		if err := s.CreateAccount(a); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, 'c', ?, ?)`,
			"h-"+a.Username, a.ID, time.Now().UTC().Add(time.Hour), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	s, err = NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession("h-sso"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("linked account session survived migration: %v", err)
	}
	if _, err := s.GetSession("h-local"); err != nil {
		t.Fatalf("local session lost in migration: %v", err)
	}
	if err := s.CreateSession(&Session{TokenHash: "h-new", UserID: linked.ID, CSRFToken: "c", ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Opening again must not run the sweep a second time.
	s, err = NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetSession("h-new"); err != nil {
		t.Fatalf("migration re-ran on reopen: %v", err)
	}
}
