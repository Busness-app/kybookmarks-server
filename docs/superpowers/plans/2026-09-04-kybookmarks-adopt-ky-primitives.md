# kybookmarks: adopt the shipped ky-primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move kybookmarks-server onto ky-primitives v0.5.0 for every primitive that applies to code already in this repo: Argon2id passwords, `keyfile` for both on-disk keys, a paper-recovery flow that verifies, `syncauth` on the directory-sync webhook, and `oidcverify` on the SSO callback.

**Architecture:** `internal/crypto` becomes a two-function adapter over `ky-primitives/password`; the salt argument disappears because PHC hashes carry their own. Both hand-rolled key loaders collapse onto `keyfile`. The paper recovery verifier is hashed server-side and the browser sends the PBKDF2-derived value. The sync webhook sits behind `syncauth.Middleware`; the OIDC callback verifies the ID token with `oidcverify.VerifyWithNonce` against a cached verifier instead of decoding an unsigned payload.

**Tech Stack:** Go 1.26, `github.com/Busness-app/ky-primitives v0.5.0` (`password`, `keyfile`, `syncauth`, `oidcverify`, `auditchain`), React + Vite frontend (no test runner; `npm run build` only), `scripts/ablate.py`.

**Spec:** myslop folders `kybookmarks-kyrecovery-deposit` (posts 154, 176, 187, 194, 197), `ky-primitives-syncauth` (posts 205, 212), `ky-primitives-oidcverify` (posts 206, 213). Library API read from ky-primitives master at 533a053 (PR #12 merged 2026-09-05). The KyRecovery half is a separate plan: `docs/superpowers/plans/2026-09-05-kybookmarks-wires-recoveryclient.md`.

## Global Constraints

- `go 1.26.6`; CI pins `go-version: '1.26'`.
- **ky-primitives `v0.5.0` is not tagged yet** (master 533a053 has everything). Task 1 pins the commit; the PR must not merge until it is re-pinned to the tag.
- Nothing is in the wild (hand-off, 2026-09-04): no rehash shim, no legacy key-file shim, no dual-accept sync window. Dev data is deleted and recreated.
- Every task is its own commit so the pr-reviewer bot reads each migration alone.
- Gate before the PR: `gofmt -l .` empty, `go mod tidy` no diff, `go vet ./...`, `go test -race ./...`, `cd frontend && npm run build`, `python3 scripts/ablate.py`.
- Worktree `.claude/worktrees/primitives`, branch `feat/adopt-ky-primitives` (superpowers:using-git-worktrees).
- The sync webhook cut-over breaks live sync from a KySignOn that still signs the old way. The kysignon sender moves to `syncauth.Sign` in its own PR (folder `ky-primitives-syncauth`, "Left"). Say so in the PR body.

## Decisions taken in this plan (posted to the board for Yoshi)

1. **`ky-primitives/recoverycode` is not adopted.** The paper key is generated in the browser because it wraps the vault key (`frontend/src/pages/LoginPage.tsx:143`); the server never sees it. `recoverycode` owns Go-side generation and leaves hashing to the caller. The client keeps its 16-symbol/80-bit generator; the dead Go generator is deleted.
2. **Paper recovery is broken in master, by code reading.** The browser stores `recoveryVerifier = PBKDF2(paperKey)` raw (`auth_handlers.go:275`, `:408`); recovery compares `scrypt(typedPaperKey)` to it (`auth_handlers.go:153`). Task 3 proves it red before fixing. Unproven until that test runs.
3. **No CLI dispatcher here.** It arrives with `restore` and `deposit` in the recoveryclient plan.
4. **The sync handler keeps reading `action` from the body.** `syncauth` binds the header event type into the signature; the handler logs a mismatch between header type and body action and refuses it, so a signed `user.update` cannot be replayed with a `user.delete` body.
5. **Userinfo is enrichment only.** After the ID token verifies, userinfo may fill a missing email or name and must return the same `sub`; it can no longer be the source of identity.

---

### Task 1: Pin ky-primitives at the recoveryclient merge

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Pin**

```bash
go get github.com/Busness-app/ky-primitives@533a053
go mod tidy
```

If `git -C /home/yoshi/busness.app/ky-primitives tag | grep -x v0.5.0` prints the tag, use `@v0.5.0` instead. Either way the PR is re-pinned to `v0.5.0` in Task 8 before merge.

- [ ] **Step 2: Prove nothing moved**

Run: `go build ./... && go test ./internal/audit/`
Expected: build clean, audit tests PASS.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore(deps): ky-primitives at recoveryclient merge (re-pin to v0.5.0 before merge)"
```

---

### Task 2: Passwords move from scrypt to Argon2id via ky-primitives/password

**Files:**
- Modify: `internal/crypto/crypto.go` (delete scrypt constants, `HashPassword`, `VerifyPassword`, the `golang.org/x/crypto/scrypt` import)
- Modify: `internal/crypto/crypto_test.go`
- Modify: `internal/api/auth_handlers.go:65,68,153,258,356,369,607`
- Modify: `internal/api/admin_handlers.go:50,124,263`
- Modify: `internal/api/access_test.go:92`

**Interfaces:**
- Produces: `crypto.HashPassword(secret string) (string, error)` returning a PHC `$argon2id$...` string; `crypto.VerifyPassword(secret, encoded string) bool`.
- `AuthSalt` stays: the browser needs it for its own PBKDF2. Only the server-side hash stops using it.

- [ ] **Step 1: Rewrite the crypto test**

Replace `TestCryptoUtils` in `internal/crypto/crypto_test.go`:

```go
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
```

- [ ] **Step 2: See it fail to compile**

Run: `go test ./internal/crypto/`
Expected: FAIL, "too many arguments in call to HashPassword".

- [ ] **Step 3: Replace the implementation**

In `internal/crypto/crypto.go` delete the `Scrypt*` constants, the scrypt import, and both functions. Add:

```go
import "github.com/Busness-app/ky-primitives/password"

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
```

- [ ] **Step 4: Update every call site**

`internal/api/auth_handlers.go`:
- `:65` → `verified = crypto.VerifyPassword(secret, acc.PasswordHash)`
- `:68` → `verified = crypto.VerifyPassword(req.Password, acc.PasswordHash)`
- `:153` → `!crypto.VerifyPassword(cleanSecret, acc.RecoveryVerifier)` (Task 3 changes this line again)
- `:258` → `hash, err := crypto.HashPassword(secretToHash)` (keep `salt`: it is still stored as `AuthSalt`)
- `:356` → `!crypto.VerifyPassword(req.OldPassword, acc.PasswordHash)`
- `:369` → `newHash, err := crypto.HashPassword(secretToHash)`
- `:607` → `pHash, _ := crypto.HashPassword(rndPass)`

`internal/api/admin_handlers.go` `:50,124,263` → drop the salt argument; keep generating and storing `salt` as `AuthSalt`.

`internal/api/access_test.go:92` → `verifier, err := crypto.HashPassword(secret)`.

- [ ] **Step 5: Tidy and run the tree**

Run: `go mod tidy && go build ./... && go test -race ./...`
Expected: PASS. `golang.org/x/crypto` moves to `// indirect` in go.mod.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/crypto internal/api
git commit -m "feat(auth): Argon2id via ky-primitives/password replaces scrypt"
```

---

### Task 3: Paper recovery verifies the derived secret, hashed server-side

**Files:**
- Create: `internal/api/recovery_test.go`
- Modify: `internal/api/auth_handlers.go` (`handlePaperRecovery:146-160`, `handleSetupInit:275`, `handleUpdateKeyWraps:407-409`)
- Modify: `internal/crypto/crypto.go` (delete `GeneratePaperRecoveryKey`), `internal/crypto/crypto_test.go`
- Modify: `frontend/src/pages/LoginPage.tsx:172-190`

**Interfaces:**
- Consumes: `crypto.HashPassword(secret)`, `crypto.VerifyPassword(secret, encoded)` from Task 2.
- Wire contract: `POST /api/setup` and `POST /api/auth/key-wraps` accept `recoveryVerifier` = hex of PBKDF2(paperKey, authSalt, kdfIterations) exactly as the browser already derives it; the server stores `HashPassword(recoveryVerifier)`. `POST /api/auth/recovery` takes `recoverySecret` = that same derived hex, never the paper key.

- [ ] **Step 1: Write the failing test**

`internal/api/recovery_test.go` (`setupTestServer` seeds no admin, so `/api/setup` is open; `post` is in `pairing_test.go:54`):

```go
package api

import (
	"net/http"
	"testing"
)

// The browser derives the verifier with PBKDF2 and posts the hex. The server must
// hash that at rest and accept the same hex back on recovery.
func TestPaperRecoveryAcceptsTheDerivedVerifier(t *testing.T) {
	srv, handler, cleanup := setupTestServer(t)
	defer cleanup()

	const verifier = "9b7d2c4e1f0a6b5c3d8e7f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c"
	w := post(t, handler, "/api/setup", map[string]any{
		"username":         "owner",
		"email":            "owner@example.com",
		"displayName":      "Owner",
		"password":         "correct-horse-battery-staple",
		"authSecret":       "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
		"authSalt":         "00112233445566778899aabbccddeeff",
		"kdfIterations":    600000,
		"passwordKeyWrap":  "wrap-under-password",
		"recoveryKeyWrap":  "wrap-under-paper-key",
		"recoveryVerifier": verifier,
	}, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("setup returned %d: %s", w.Code, w.Body.String())
	}

	acc, err := srv.store.GetAccountByUsernameOrEmail("owner")
	if err != nil {
		t.Fatal(err)
	}
	if acc.RecoveryVerifier == verifier {
		t.Fatal("recovery verifier stored in the clear; it must be hashed like the password")
	}

	w = post(t, handler, "/api/auth/recovery", map[string]string{
		"username":       "owner",
		"recoverySecret": verifier,
	}, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("recovery with the derived verifier returned %d: %s", w.Code, w.Body.String())
	}

	w = post(t, handler, "/api/auth/recovery", map[string]string{
		"username":       "owner",
		"recoverySecret": "9b7d2c4e1f0a6b5c3d8e7f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9d",
	}, nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("recovery with a wrong verifier returned %d, want 401", w.Code)
	}
}
```

Add a second test that logs in, posts `{"recoveryVerifier": "<hex>"}` to `/api/auth/key-wraps` with the session and CSRF cookies (see how `pairing_test.go` obtains them), and asserts the stored column differs from the posted value.

- [ ] **Step 2: Run it red**

Run: `go test ./internal/api/ -run TestPaperRecovery -v`
Expected: FAIL at "stored in the clear". Paste this output in the PR as the proof for decision 2.

- [ ] **Step 3: Hash the verifier on write**

`handleSetupInit`, before building `admin`:

```go
	recoveryVerifier := ""
	if req.RecoveryVerifier != "" {
		v, err := crypto.HashPassword(req.RecoveryVerifier)
		if err != nil {
			http.Error(w, "failed to hash recovery verifier", http.StatusInternalServerError)
			return
		}
		recoveryVerifier = v
	}
```
and `RecoveryVerifier: recoveryVerifier,` in the struct literal.

`handleUpdateKeyWraps`:

```go
	if req.RecoveryVerifier != "" {
		v, err := crypto.HashPassword(req.RecoveryVerifier)
		if err != nil {
			http.Error(w, "failed to hash recovery verifier", http.StatusInternalServerError)
			return
		}
		acc.RecoveryVerifier = v
	}
```

- [ ] **Step 4: Verify the derived secret on recovery**

In `handlePaperRecovery` replace the `cleanSecret` line and the check:

```go
	secret := strings.TrimSpace(req.RecoverySecret)
	if acc.RecoveryVerifier == "" || !crypto.VerifyPassword(secret, acc.RecoveryVerifier) {
```

Comment above the lockout: "Without it this is an unmetered Argon2id oracle."

- [ ] **Step 5: Delete the dead generator**

Remove `GeneratePaperRecoveryKey` from `internal/crypto/crypto.go`. `grep -rn GeneratePaperRecoveryKey --include='*.go' .` must return nothing.

- [ ] **Step 6: Run green**

Run: `go test -race ./...`
Expected: PASS, including `TestRecoveryRefusesSuspendedAccount` and `TestRecoveryLocksOutAfterRepeatedFailures`.

- [ ] **Step 7: The browser derives before it posts**

`frontend/src/pages/LoginPage.tsx`, `handleRecoverySubmit`:

```ts
      const targetUser = loggedInUser?.username || username;
      const params = await getJSON<{ salt: string; iterations: number }>(
        `/api/auth/login-params?username=${encodeURIComponent(targetUser)}`
      );
      const cleanPaper = recoverySecret.replace(/-/g, '').toUpperCase();
      const derived = await deriveAuthSecret(cleanPaper, params.salt, params.iterations);

      const res = await postJSON<{ ok: boolean; user: any }>('/api/auth/recovery', {
        username: targetUser,
        recoverySecret: derived,
      });

      const paperWrappingKey = await deriveKeyFromPassword(cleanPaper, res.user.authSalt, res.user.kdfIterations || 600000);
      const vaultKey = await unwrapVaultKey(res.user.recoveryKeyWrap, paperWrappingKey);
```

`/api/auth/login-params` already serves a stable decoy salt for unknown users, so this leaks nothing login does not.

- [ ] **Step 8: Build and click through**

Run: `cd frontend && npm run build`
With a throwaway `DATA_DIR`: set up an admin, copy the paper key from Security Settings, log out, recover with it. Expected: session opens and bookmarks decrypt.

- [ ] **Step 9: Commit**

```bash
git add internal/api internal/crypto frontend/src/pages/LoginPage.tsx
git commit -m "fix(auth): paper recovery verifies the derived secret, hashed at rest"
```

---

### Task 4: Both key files through ky-primitives/keyfile

**Files:**
- Modify: `internal/audit/audit.go:162-222` (`loadOrCreateKey`, delete `decodeKey`)
- Modify: `internal/api/server.go:101-131` (`loadOrCreateSaltKey`)
- Modify: `scripts/ablate.py:23-25`
- Modify: `AGENTS.md` audit table (`AUDIT_KEY` row)

**Interfaces:**
- `AUDIT_KEY` becomes exactly 32 bytes, hex or base64 (was: hex, at least 32). A set-but-wrong value is a boot error, never a fallthrough.
- `audit.key` and `enum.key` stay lowercase hex at 0600; files written without a trailing newline still read.

- [ ] **Step 1: Pin the env contract**

Append to `internal/audit/key_test.go`:

```go
func TestAuditKeyEnvAcceptsBase64AndRefusesWrongLength(t *testing.T) {
	root := t.TempDir()
	t.Setenv(keyEnv, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") // 32 zero bytes, base64
	if _, err := NewLogger(filepath.Join(root, "audit"), filepath.Join(root, "config"), ""); err != nil {
		t.Fatalf("base64 AUDIT_KEY refused: %v", err)
	}
	t.Setenv(keyEnv, strings.Repeat("ab", 33))
	if _, err := NewLogger(filepath.Join(root, "audit2"), filepath.Join(root, "config2"), ""); err == nil {
		t.Fatal("AUDIT_KEY of 33 bytes accepted; keyfile requires exactly 32")
	}
}
```

- [ ] **Step 2: Run it red**

Run: `go test ./internal/audit/ -run TestAuditKeyEnv -v`
Expected: FAIL (base64 refused by `decodeKey`).

- [ ] **Step 3: Replace the audit loader**

```go
import "github.com/Busness-app/ky-primitives/keyfile"

// loadOrCreateKey sources the chain key from AUDIT_KEY, else configDir/audit.key,
// else 32 fresh random bytes persisted 0600. There is deliberately no constant fallback.
func loadOrCreateKey(configDir string) ([]byte, error) {
	if key, ok, err := keyfile.FromEnv(keyEnv, keyLen); err != nil {
		return nil, err
	} else if ok {
		return key, nil
	}
	return keyfile.LoadOrCreate(filepath.Join(configDir, keyFile), keyLen)
}
```

Delete `decodeKey` and the imports `go vet` reports unused.

- [ ] **Step 4: Replace the decoy salt loader**

`internal/api/server.go`:

```go
func loadOrCreateSaltKey(configDir string) ([]byte, error) {
	if configDir == "" {
		return nil, errors.New("decoy salt key: no config directory to persist it in")
	}
	key, err := keyfile.LoadOrCreate(filepath.Join(configDir, "enum.key"), 32)
	if err != nil {
		return nil, fmt.Errorf("decoy salt key: %w", err)
	}
	return key, nil
}
```

`salt_key_test.go` stays and must still pass.

- [ ] **Step 5: Run green**

Run: `go vet ./... && go test -race ./internal/audit/ ./internal/api/`
Expected: PASS, including `TestKeyIsNotAConstant`, `TestAuditKeyEnvMustBeStrong`, both salt-key tests.

- [ ] **Step 6: Keep the ablation honest**

`scripts/ablate.py` first entry no longer matches a source line. Replace it with:

```python
 ("constant key fallback", AUDIT, "TestKeyIsNotAConstant|TestForgery",
  "\treturn keyfile.LoadOrCreate(filepath.Join(configDir, keyFile), keyLen)",
  "\treturn []byte(legacyDefaultSecret + legacyDefaultSecret)[:keyLen], nil"),
```

Run: `python3 scripts/ablate.py`
Expected: every ablation caught.

- [ ] **Step 7: Docs**

`AGENTS.md` audit table, `AUDIT_KEY` row: "Optional. Exactly 32 bytes as hex (`openssl rand -hex 32`) or base64. A value that is set but malformed refuses to start. Unset means the server generates a key into `CONFIG_DIR/audit.key` (0600) on first run." Under "Rules" add: "Both on-disk keys (`audit.key`, `enum.key`) are read and minted through `ky-primitives/keyfile`; do not add a third reader."

- [ ] **Step 8: Commit**

```bash
git add internal/audit internal/api/server.go scripts/ablate.py AGENTS.md
git commit -m "refactor: audit.key and enum.key through ky-primitives/keyfile"
```

---

### Task 5: Directory-sync webhook behind syncauth.Middleware

**Files:**
- Modify: `internal/api/admin_handlers.go:220-240` (`handleDirectorySyncEvent`: drop the HMAC block, add the type check)
- Modify: `internal/api/server.go:222` (route), plus a `syncReplay` field on `Server`
- Modify: `internal/api/api_test.go:231-243` (`syncRequest`), new cases
- Modify: `scripts/ablate.py:129-131`

**Interfaces:**
- Consumes: `syncauth.Middleware(keyFn, Options, maxBody, onReject)`, `syncauth.NewMemoryReplay(window, max)`, `syncauth.EventFromContext(r)`, `syncauth.Sign(key, at, eventType, eventID, body)`, `(Headers).Apply(r)`.
- Wire contract (sender side lands in kysignon separately): headers `X-KySignOn-Signature: v1=<hex>`, `X-KySignOn-Timestamp`, `X-KySignOn-Event-Type`, `X-KySignOn-Event-ID`; no bearer. The header event type must equal the body's `action`.

- [ ] **Step 1: Rewrite the test helper and add cases**

Replace `syncRequest` in `internal/api/api_test.go`:

```go
func syncRequest(t *testing.T, handler http.Handler, secret, body string) int {
	t.Helper()
	return syncRequestTyped(t, handler, secret, "user.create", "evt-"+body[:8], body, time.Now())
}

func syncRequestTyped(t *testing.T, handler http.Handler, secret, eventType, eventID, body string, at time.Time) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/sync/events", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		h, err := syncauth.Sign([]byte(secret), at, eventType, eventID, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		h.Apply(req)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code
}
```

Add after `TestDirectorySyncFailsClosedWithoutSecret`:

```go
// The header type is inside the signature; the body's action must agree with it, or a
// captured user.update could be replayed carrying a user.delete body.
func TestDirectorySyncRefusesTypeMismatchStaleAndReplay(t *testing.T) {
	_, handler, cleanup := setupTestServer(t)
	defer cleanup()
	const body = `{"action":"user.delete","user":{"id":"sso-3","username":"gone"}}`

	if code := syncRequestTyped(t, handler, "test-sync-secret", "user.update", "evt-mismatch", body, time.Now()); code != http.StatusUnauthorized {
		t.Errorf("type mismatch: got %d, want 401", code)
	}
	if code := syncRequestTyped(t, handler, "test-sync-secret", "user.delete", "evt-stale", body, time.Now().Add(-10*time.Minute)); code != http.StatusUnauthorized {
		t.Errorf("stale timestamp: got %d, want 401", code)
	}
	if code := syncRequestTyped(t, handler, "test-sync-secret", "user.delete", "evt-once", body, time.Now()); code != http.StatusOK {
		t.Fatalf("first delivery: got %d, want 200", code)
	}
	if code := syncRequestTyped(t, handler, "test-sync-secret", "user.delete", "evt-once", body, time.Now()); code != http.StatusUnauthorized {
		t.Errorf("replayed event id: got %d, want 401", code)
	}
}
```

- [ ] **Step 2: Run red**

Run: `go test ./internal/api/ -run TestDirectorySync -v`
Expected: `TestDirectorySyncRequiresSignature` FAILS (old handler expects the bare HMAC), the new test FAILS.

- [ ] **Step 3: Install the middleware**

`internal/api/server.go`: add `syncReplay syncauth.Replay` to `Server`; in `NewServer`: `syncReplay: syncauth.NewMemoryReplay(0, 0)`. Route:

```go
	mux.Handle("POST /api/sync/events", s.syncAuth()(http.HandlerFunc(s.handleDirectorySyncEvent)))
```

and, next to `withAdmin`:

```go
// syncAuth verifies the KySignOn signature before the handler decodes anything. An empty
// SYNC_SECRET is a 401 from the middleware (keyFn error), which keeps the old fail-closed
// behaviour without a second check in the handler.
func (s *Server) syncAuth() func(http.Handler) http.Handler {
	keyFn := func(*http.Request) ([]byte, error) {
		if s.cfg.SyncSecret == "" {
			return nil, errors.New("SYNC_SECRET is not set")
		}
		return []byte(s.cfg.SyncSecret), nil
	}
	onReject := func(r *http.Request, err error) {
		log.Printf("sync: rejected event from %s: %v", clientIP(r), err)
	}
	return syncauth.Middleware(keyFn, syncauth.Options{Replay: s.syncReplay}, 0, onReject)
}
```

`handleDirectorySyncEvent`: delete the `SyncSecret == ""` block and the `hmac` block (lines 226-238). After `json.Unmarshal`:

```go
	ev, _ := syncauth.EventFromContext(r)
	if ev.Type != event.Action {
		s.auditEvent(r, "sync.rejected", "", "", "signed type "+syncauthSafe(ev.Type)+" does not match body action "+syncauthSafe(event.Action))
		http.Error(w, `{"error":"invalid_signature"}`, http.StatusUnauthorized)
		return
	}
```

with `func syncauthSafe(s string) string { return recoveryclient.AuditSafe(s) }` replaced by a local 200-byte printable bound if you do not want the recoveryclient import yet: copy the loop from ky-primitives `recoveryclient/client.go:294`.

Drop the now-unused `crypto/hmac`, `crypto/sha256`, `encoding/hex` imports in `admin_handlers.go`.

- [ ] **Step 4: Run green**

Run: `go test -race ./internal/api/`
Expected: PASS. `TestDirectorySyncFailsClosedWithoutSecret` still passes via the keyFn error.

- [ ] **Step 5: Ablation**

Replace the "sync signature optional again" entry in `scripts/ablate.py` (target `SERVER`, not `ADMIN`):

```python
 ("sync signature optional again", SERVER, "TestDirectorySync",
  '\tmux.Handle("POST /api/sync/events", s.syncAuth()(http.HandlerFunc(s.handleDirectorySyncEvent)))',
  '\tmux.HandleFunc("POST /api/sync/events", s.handleDirectorySyncEvent)'),
```

Run: `python3 scripts/ablate.py`. Expected: caught.

- [ ] **Step 6: Commit**

```bash
git add internal/api scripts/ablate.py
git commit -m "feat(sync): verify KySignOn events with ky-primitives/syncauth"
```

---

### Task 6: SSO callback verifies the ID token with oidcverify

**Files:**
- Modify: `internal/sso/sso.go:184-252` (delete `ParseClaims`; add `NewVerifier`, `VerifiedClaims`)
- Create: `internal/sso/verify_test.go`
- Modify: `internal/api/auth_handlers.go:441-460` (nonce into the flow), `:518-523` (cookie parts), `:550` (call site)
- Modify: `internal/api/server.go` (`oidc` verifier cache on `Server`)

**Interfaces:**
- Consumes: `oidcverify.Verifier{Issuer, Audience, HTTPClient}`, `(*Verifier).VerifyWithNonce(ctx, token, nonce) (oidcverify.Claims, error)`, `Claims.Subject`, `Claims.String(name)`, `Claims.Raw`.
- Produces:

```go
// internal/sso
func NewVerifier(issuer, clientID string, httpClient *http.Client) *oidcverify.Verifier
func VerifiedClaims(ctx context.Context, v *oidcverify.Verifier, idToken, nonce, accessToken, userinfoEndpoint string) (*Claims, error)
```

The SSO cookie becomes `state|verifier|linkUserID|nonce`.

- [ ] **Step 1: Failing test**

`internal/sso/verify_test.go`. Mint a token with a generated RSA key and serve its JWKS from `httptest.NewTLSServer`; the server's URL is the issuer, its `Client()` is the verifier's HTTP client:

```go
package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mintRS256(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	pl, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc(hdr) + "." + enc(pl)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, 0, sum[:]) // crypto.SHA256 == 5; use crypto.SHA256 in real code
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}

func TestVerifiedClaimsAcceptsAGoodTokenAndRefusesAlgNone(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		enc := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	v := NewVerifier(srv.URL, "kybookmarks", srv.Client())
	now := time.Now().Unix()
	good := mintRS256(t, key, map[string]any{
		"iss": srv.URL, "aud": "kybookmarks", "sub": "user-1", "nonce": "n1",
		"email": "u@example.com", "email_verified": true, "preferred_username": "u", "role": "admin",
		"iat": now, "exp": now + 300,
	})
	claims, err := VerifiedClaims(context.Background(), v, good, "n1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" || claims.Email != "u@example.com" || !claims.EmailVerified || claims.Role != "admin" || claims.Username != "u" {
		t.Fatalf("claims: %+v", claims)
	}

	if _, err := VerifiedClaims(context.Background(), v, good, "other-nonce", "", ""); err == nil {
		t.Fatal("wrong nonce accepted")
	}

	parts := strings.Split(good, ".")
	hdr, _ := json.Marshal(map[string]string{"alg": "none"})
	none := base64.RawURLEncoding.EncodeToString(hdr) + "." + parts[1] + "."
	if _, err := VerifiedClaims(context.Background(), v, none, "n1", "", ""); err == nil {
		t.Fatal("alg=none accepted; this is the bug the package exists to remove")
	}
}
```

Use `crypto.SHA256` (import `crypto`) as the hash argument to `rsa.SignPKCS1v15`, not the literal.

- [ ] **Step 2: Run red**

Run: `go test ./internal/sso/ -run TestVerifiedClaims`
Expected: FAIL, undefined `NewVerifier`.

- [ ] **Step 3: Implement in sso.go**

Delete `ParseClaims`. Add:

```go
import "github.com/Busness-app/ky-primitives/oidcverify"

// NewVerifier builds a JWKS-backed verifier for one issuer and this client. Callers keep it
// alive across logins so the JWKS cache and its refresh rate limit do their job.
func NewVerifier(issuer, clientID string, httpClient *http.Client) *oidcverify.Verifier {
	return &oidcverify.Verifier{Issuer: issuer, Audience: clientID, HTTPClient: httpClient}
}

// VerifiedClaims checks the ID token's signature, issuer, audience, lifetime and nonce, then
// reads the profile claims from it. Userinfo may fill a missing email or name and must
// report the same subject; it is never the source of identity.
func VerifiedClaims(ctx context.Context, v *oidcverify.Verifier, idToken, nonce, accessToken, userinfoEndpoint string) (*Claims, error) {
	if idToken == "" {
		return nil, errors.New("identity provider returned no ID token")
	}
	vc, err := v.VerifyWithNonce(ctx, idToken, nonce)
	if err != nil {
		return nil, err
	}
	claims := &Claims{
		Subject:  vc.Subject,
		Email:    vc.String("email"),
		Name:     vc.String("name"),
		Username: vc.String("preferred_username"),
		Role:     vc.String("role"),
	}
	if raw, ok := vc.Raw["email_verified"]; ok {
		_ = json.Unmarshal(raw, &claims.EmailVerified)
	}

	if (claims.Email == "" || claims.Name == "") && userinfoEndpoint != "" && accessToken != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+accessToken)
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				var u Claims
				if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&u) == nil && u.Subject == claims.Subject {
					if claims.Email == "" {
						claims.Email, claims.EmailVerified = u.Email, u.EmailVerified
					}
					if claims.Name == "" {
						claims.Name = u.Name
					}
				}
			}
		}
	}

	if claims.Username == "" {
		if claims.Email != "" {
			claims.Username = strings.Split(claims.Email, "@")[0]
		} else {
			claims.Username = claims.Subject
		}
	}
	return claims, nil
}
```

- [ ] **Step 4: Run green**

Run: `go test ./internal/sso/`
Expected: PASS.

- [ ] **Step 5: Wire nonce and verifier into the handlers**

`internal/api/server.go`: fields

```go
	oidcMu     sync.Mutex
	oidcIssuer string
	oidcClient string
	oidc       *oidcverify.Verifier
```

and

```go
// verifierFor returns one verifier per (issuer, client id) so the JWKS cache survives across
// logins, and rebuilds it when an admin changes the SSO settings.
func (s *Server) verifierFor(settings sso.SSOSettings) *oidcverify.Verifier {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.oidc == nil || s.oidcIssuer != settings.IssuerURL || s.oidcClient != settings.ClientID {
		s.oidc = sso.NewVerifier(settings.IssuerURL, settings.ClientID, nil)
		s.oidcIssuer, s.oidcClient = settings.IssuerURL, settings.ClientID
	}
	return s.oidc
}
```

`handleSSOStart` (`auth_handlers.go:449-453`): mint a nonce beside the state and carry it:

```go
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)
	cookieVal := fmt.Sprintf("%s|%s|%s|%s", state, verifier, linkUserID, nonce)
```
and `q.Set("nonce", nonce)` with the other query parameters.

`handleSSOCallback` (`:518-523`): require four parts.

```go
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 4 || subtle.ConstantTimeCompare([]byte(parts[0]), []byte(state)) != 1 {
		http.Error(w, "invalid SSO state parameter", http.StatusBadRequest)
		return
	}
	codeVerifier, linkUserID, nonce := parts[1], parts[2], parts[3]
```

`:550`: `claims, err := sso.VerifiedClaims(r.Context(), s.verifierFor(settings), tok.IDToken, nonce, tok.AccessToken, disc.UserinfoEndpoint)`; on error answer 502 with "identity token failed verification" and audit `sso.token_rejected` with the error text (bounded).

`sso_callback_test.go` exists: update its cookie construction to four parts and its fake provider to mint an RS256 token and serve a JWKS (reuse `mintRS256` by moving it to an exported test helper in `internal/sso/testhelp_test.go` is not possible across packages; duplicate the ten lines in `internal/api`).

- [ ] **Step 6: Run green, build, commit**

Run: `go test -race ./... && cd frontend && npm run build`
Expected: PASS.

```bash
git add internal/sso internal/api
git commit -m "feat(sso): verify KySignOn ID tokens with ky-primitives/oidcverify"
```

---

### Task 7: Docs catch up with the code

**Files:**
- Delete: `zero_code_pairing_handoff_spec.md`
- Modify: `AGENTS.md:1-14` (capabilities 1, 4), `AGENTS.md:161`, `docker-compose.yml:29-31`

- [ ] **Step 1: Remove the stale v1 spec**

```bash
git rm zero_code_pairing_handoff_spec.md
```

- [ ] **Step 2: Fix the Child DOX Index**

Replace the `zero_code_pairing_handoff_spec.md` bullet at `AGENTS.md:161` with:

```
- KyRecovery pairing and deposit: `docs/superpowers/plans/2026-09-05-kybookmarks-wires-recoveryclient.md`. The suite contract is `kyrecovery-server/zero_code_pairing_handoff_spec.md` v2.0.0; the product side is `ky-primitives/recoveryclient`. Do not copy `internal/backup` from another product.
```

- [ ] **Step 3: Record the contracts**

Capability 1, append: "Login and paper-recovery secrets are derived in the browser with PBKDF2 and stored server-side as Argon2id (`ky-primitives/password`); the paper key itself never reaches the server."

Capability 4, replace the parenthetical with: "signed directory-sync webhook (`/api/sync/events`, verified by `ky-primitives/syncauth`: signature, timestamp window, event id replay guard, header type must equal body action) and ID tokens verified by `ky-primitives/oidcverify` against the issuer's JWKS with a per-login nonce."

Add after "Audit chain":

```
## Passwords and the paper key

`internal/crypto.HashPassword` and `VerifyPassword` wrap `ky-primitives/password`
(Argon2id, RFC 9106 second profile, PHC-encoded). `AuthSalt` is the browser's PBKDF2
salt, not the server's; the server hash carries its own. The paper recovery key is
generated in the browser because it wraps the vault key, so `ky-primitives/recoverycode`
(server-side generation) does not apply here. The browser posts
`recoveryVerifier = PBKDF2(paperKey)` at enrolment and the same value as `recoverySecret`
at recovery; the server stores and checks it exactly like a password.
```

`docker-compose.yml` `SYNC_SECRET` comment: add "At least 16 bytes; KySignOn mints 32. The secret is the HMAC key and never travels in a header."

- [ ] **Step 4: Commit**

```bash
git add AGENTS.md docker-compose.yml
git commit -m "docs: drop the v1 pairing spec; record Argon2id, sync and OIDC contracts"
```

---

### Task 8: Gate, PR, board

- [ ] **Step 1: Re-pin to the tag**

```bash
git -C /home/yoshi/busness.app/ky-primitives fetch --tags -q && git -C /home/yoshi/busness.app/ky-primitives tag | grep -x v0.5.0
go get github.com/Busness-app/ky-primitives@v0.5.0 && go mod tidy
```

If the tag is still absent, stop here and post to `ky-primitives-kyrecovery-package` that this PR waits on it.

- [ ] **Step 2: Full gate**

```bash
gofmt -l . ; go mod tidy && git diff --exit-code go.mod go.sum
go vet ./... && go test -race ./...
cd frontend && npm run build && cd ..
python3 scripts/ablate.py
```
Expected: all clean. Paste the summary lines into the PR body.

- [ ] **Step 3: Open the PR**

Use the `pull-request` skill. Title: "Adopt ky-primitives v0.5.0: Argon2id, keyfile, syncauth, oidcverify, working paper recovery". Body: the five decisions above, the red-test output from Task 3 Step 2, and the note that live sync from KySignOn resumes when its sender moves to `syncauth.Sign`.

- [ ] **Step 4: Board**

Post to `kybookmarks-kyrecovery-deposit` (skill `myslop-handoff`): what landed, that the deposit half is the second plan, and the SecuritySettings hazard below.

## Careful

- Argon2id at 64 MiB per derivation: `go test -race ./...` gets slower and `password.Verify` can shed under `-p` parallelism, which `VerifyPassword` reports as false. If a test flakes on a correct secret, run that package with `-p 1` before blaming the code.
- `frontend/src/pages/SecuritySettings.tsx:99` generates a paper key with `user.authSalt || generateRandomHex(16)`. For an account with no `authSalt` (SSO-provisioned) the random salt is never stored, so that verifier can never be re-derived. Pre-existing, out of scope, on the board.
- `AUDIT_KEY` length changes from "at least 32" to "exactly 32". Nothing is deployed; if that assumption is wrong the boot error names the variable.
- `syncauth.MinKeyBytes` is 16. The test fixture's `test-sync-secret` is exactly 16 bytes; a shorter dev secret is a 401 with "key unavailable" in the log, not a silent accept.
- `oidcverify` refuses a plaintext issuer before any request. A dev KySignOn on `http://` cannot log in after Task 6; run it behind TLS or document the limitation. Do not add an insecure switch.
- Do not touch `internal/audit` chain logic while swapping the loader. `TestChainIsDrivenFromOneCallSite` and the ablations will tell you if the edit strayed.
