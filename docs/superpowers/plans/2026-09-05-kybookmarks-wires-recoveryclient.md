# kybookmarks wires ky-primitives `recoveryclient` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring kybookmarks-server to the KySignOn backup spec by wiring `github.com/Busness-app/ky-primitives/recoveryclient`: pin or pair, seal, local copies, schedule, deposit, drill, restore, screen, runbook.

**Architecture:** A new `internal/backup` package holds only what is product-specific: a `Settings` adapter over a new `settings` table, a `Sealer` under a new deployment key minted by `keyfile`, `Collect` (SQLite `VACUUM INTO` through the live handle plus every key and config file a restore needs), and the drill's checks. `internal/api/backup_handlers.go` maps the lib onto eight admin routes. `cmd/server/main.go` gains a subcommand dispatcher, a minute-polling backup loop, and a ten-line `restore`. The admin panel gets a Backup tab ported from kysignon.

**Tech Stack:** Go 1.26, `ky-primitives v0.5.0` (`recoveryclient`, `recoveryclient/guardtest`, `keyfile`, `capsule`), `modernc.org/sqlite`, React + Vite (no test runner), Docker Compose.

**Spec:** ky_server_base `docs/superpowers/plans/2026-09-04-bring-suite-to-kysignon-spec.md` (fourteen rows), suite `/home/yoshi/busness.app/AGENTS.md` "KyRecovery integration", myslop folder `kybookmarks-kyrecovery-deposit` post 194. Reference product code: `kysignon-server` master (`internal/api/backup_handlers.go`, `cmd/kysignon/main.go`, `web/src/components/AdminBackup.tsx`, `docs/RESTORE.md`). Reference adaptation against the lib: ky_server_base `docs/superpowers/plans/2026-09-04-scaffold-wires-recoveryclient.md`. Library API read from ky-primitives master 533a053.

## Global Constraints

- **After** `docs/superpowers/plans/2026-09-04-kybookmarks-adopt-ky-primitives.md` merges (it pins the lib and gives `internal/audit`/`internal/api` their keyfile loaders). Branch from that.
- **Blocked until** ky-primitives `v0.5.0` is tagged. Pin the tag, not a commit, before the PR.
- Lib facts: `Drill(ctx, scratchRoot, payload, checks)` refuses an empty root; `WriteLocalCopy` refuses `Keep < 1`; `SQLiteSnapshot(ctx, db, destPath)` wants a non-existent dest; local copies are `<escaped-app>.<capsule-id>.kycap`; `guardtest.MinFiles` is 10; `Settings.Get` must return `recoveryclient.ErrNotFound` for a never-written key.
- Service name `KyBookmarks` (matches `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`). Sealer label `kybookmarks:setting:kyrecovery_token`.
- Env: `KYBOOKMARKS_BACKUP_DIR` (default empty = off), `KYBOOKMARKS_BACKUP_KEEP` (7), `KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL` (`24h`, the default only), `KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY` (false), `KYBOOKMARKS_DNS` (compose override only). A new `CONFIG_DIR/deployment.key` (32 bytes via `keyfile.LoadOrCreate`) seals the token.
- Routes under `/api/admin/backup/...` behind `withAdmin` (admin role + CSRF). **Step-up:** this product has none. Spec row 10 says "or the product's equivalent"; admin role plus CSRF is what exists. Say so in AGENTS.md and the PR (assumption).
- Audit through `s.auditEvent(r, action, userID, deviceID, details string)` / `s.audit.Log(ctx, ...)`; the lib's `details map[string]any` is flattened by `backup.AuditDetails`.
- Gate before every commit that touches Go: `go vet ./... && go test -race ./...`; frontend: `npm run build`; end: `python3 scripts/ablate.py`.
- Worktree `.claude/worktrees/deposit`, branch `feat/kyrecovery-deposit`. Claim `kybookmarks-kyrecovery-deposit` before starting.

## File map

```
internal/store/store.go              settings table; GetSetting/SetSetting/DeleteSetting
internal/api/server.go               Config{Backup BackupConfig; DeploymentKey []byte; AppVersion string}; routes; recovery client field
internal/api/backup_handlers.go      eight handlers
internal/api/backup_test.go          handler tests
internal/backup/backup.go            AppName, settings adapter, NewSealer, RunConfig, AuditDetails, DrillRoot
internal/backup/payload.go           Collect (snapshot + keys + config + manifest), Members
internal/backup/drill.go             Checks
internal/backup/*_test.go            WAL row test, adapter test, checks test
internal/backup/nodecrypt_test.go    guardtest.NoDecryptOutside
cmd/server/main.go                   dispatcher: serve (default), backup-drill, export-capsule, deposit, restore; backupLoop
frontend/src/pages/AdminBackup.tsx   ported from kysignon AdminBackup.tsx
frontend/src/pages/AdminPanel.tsx    fourth tab
docker-compose.yml, docker-compose.lan-dns.yml, Dockerfile
docs/RESTORE.md, README.md (new), AGENTS.md
```

---

### Task 1: Settings table, deployment key, backup config

**Files:**
- Modify: `internal/store/store.go` (schema after `tombstones`, three methods at the end)
- Modify: `internal/api/server.go:33-40` (`Config`)
- Modify: `cmd/server/main.go:22-80` (env parsing, key)
- Test: `internal/store/settings_test.go` (new), `cmd/server/config_test.go` (new)

**Interfaces:**
- Produces:

```go
// store
func (s *Store) GetSetting(key string) (string, error)   // ErrNotFound when never written
func (s *Store) SetSetting(key, value string) error       // upsert
func (s *Store) DeleteSetting(key string) error           // idempotent
// api
type BackupConfig struct {
	Dir                  string
	Keep                 int
	DepositInterval      time.Duration
	AllowPrivateRecovery bool
}
type Config struct { WebDir, DataDir, ConfigDir, SyncSecret string; Backup BackupConfig; DeploymentKey []byte; AppVersion string }
// cmd/server
func loadBackupConfig() (api.BackupConfig, error)
```

- [ ] **Step 1: Failing tests**

```go
// internal/store/settings_test.go
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
```

```go
// cmd/server/config_test.go
package main

import (
	"strings"
	"testing"
	"time"
)

func TestBackupConfigFromEnv(t *testing.T) {
	t.Setenv("KYBOOKMARKS_BACKUP_DIR", "/tmp/x")
	t.Setenv("KYBOOKMARKS_BACKUP_KEEP", "3")
	t.Setenv("KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL", "1h")
	t.Setenv("KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY", "true")
	cfg, err := loadBackupConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dir != "/tmp/x" || cfg.Keep != 3 || cfg.DepositInterval != time.Hour || !cfg.AllowPrivateRecovery {
		t.Fatalf("%+v", cfg)
	}
}

func TestBackupConfigRefusesKeepBelowOneAndShortInterval(t *testing.T) {
	t.Setenv("KYBOOKMARKS_BACKUP_KEEP", "0")
	if _, err := loadBackupConfig(); err == nil || !strings.Contains(err.Error(), "KYBOOKMARKS_BACKUP_KEEP") {
		t.Fatalf("keep=0: %v", err)
	}
	t.Setenv("KYBOOKMARKS_BACKUP_KEEP", "7")
	t.Setenv("KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL", "5m")
	if _, err := loadBackupConfig(); err == nil || !strings.Contains(err.Error(), "15m") {
		t.Fatalf("5m interval: %v", err)
	}
}
```

- [ ] **Step 2: Run red**

Run: `go test ./internal/store/ -run Settings; go test ./cmd/server/ -run BackupConfig`
Expected: FAIL (undefined).

- [ ] **Step 3: Store**

Append to the schema string in `migrate`:

```sql
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
```

At the end of `store.go`:

```go
func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`, key, value)
	return err
}

func (s *Store) DeleteSetting(key string) error {
	_, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, key)
	return err
}
```

- [ ] **Step 4: Config**

`internal/api/server.go` `Config`: add the three fields and the `BackupConfig` type from Interfaces.

`cmd/server/main.go`:

```go
const appVersion = "0.2.0" // bump with releases; the capsule manifest records it

func loadBackupConfig() (api.BackupConfig, error) {
	cfg := api.BackupConfig{Dir: os.Getenv("KYBOOKMARKS_BACKUP_DIR"), Keep: 7, DepositInterval: 24 * time.Hour}
	if v := os.Getenv("KYBOOKMARKS_BACKUP_KEEP"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return cfg, fmt.Errorf("KYBOOKMARKS_BACKUP_KEEP: must be an integer of at least 1, got %q", v)
		}
		cfg.Keep = n
	}
	if v := os.Getenv("KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL: %w", err)
		}
		if d != 0 && d < recoveryclient.MinInterval {
			return cfg, fmt.Errorf("KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL: %s is below the 15m floor (0 disables)", v)
		}
		cfg.DepositInterval = d
	}
	cfg.AllowPrivateRecovery = strings.EqualFold(os.Getenv("KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY"), "true")
	return cfg, nil
}
```

In `main` after `configDir` is known:

```go
	backupCfg, err := loadBackupConfig()
	if err != nil {
		log.Fatal(err)
	}
	if backupCfg.AllowPrivateRecovery {
		log.Println("KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY is on: private and CGNAT KyRecovery destinations admitted (HTTPS still required)")
	}
	deploymentKey, err := keyfile.LoadOrCreate(filepath.Join(configDir, "deployment.key"), 32)
	if err != nil {
		log.Fatalf("deployment key: %v", err)
	}
```

and `Backup: backupCfg, DeploymentKey: deploymentKey, AppVersion: appVersion` in the `api.Config` literal.

- [ ] **Step 5: Green, commit**

Run: `go build ./... && go test ./internal/store/ ./cmd/server/`
Expected: PASS.

```bash
git add internal/store internal/api/server.go cmd/server
git commit -m "store+config: settings table, deployment key, backup env"
```

---

### Task 2: `internal/backup`: adapters, collector, checks

**Files:**
- Create: `internal/backup/backup.go`, `payload.go`, `drill.go`, `backup_test.go`, `payload_test.go`, `drill_test.go`

**Interfaces:**
- Consumes: `store.GetSetting/SetSetting/DeleteSetting`, `store.DB()`, `api.Config` is not imported (avoid the cycle): the package takes plain values.
- Produces:

```go
const AppName = "KyBookmarks"
func Settings(s *store.Store) recoveryclient.Settings
func NewSealer(deploymentKey []byte) (recoveryclient.Sealer, error)
func RunConfig(dataDir, backupDir string, keep int, appVersion string, sealer recoveryclient.Sealer) recoveryclient.RunConfig
func AuditDetails(m map[string]any) string
func DrillRoot(dataDir string) string
func Members(dataDir, configDir string) []string
func Collect(ctx context.Context, st *store.Store, dataDir, configDir, appVersion string) (recoveryclient.Payload, error)
func Checks(payload recoveryclient.Payload) func(dir string) []recoveryclient.Check
```

- [ ] **Step 1: Failing tests**

```go
// internal/backup/backup_test.go
package backup

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
	got := AuditDetails(map[string]any{"b": 2, "a": "x\ny"})
	if got != "a=x?y b=2" && !strings.HasPrefix(got, "a=") {
		t.Fatalf("%q", got)
	}
	if len(AuditDetails(map[string]any{"k": strings.Repeat("z", 1000)})) > 200 {
		t.Fatal("unbounded")
	}
}
```

```go
// internal/backup/payload_test.go
package backup

// A commit still in the WAL must be in the snapshot; copying the file would miss it.
func TestCollectSeesUncheckpointedCommit(t *testing.T) {
	dataDir := t.TempDir()
	configDir := filepath.Join(dataDir, "config")
	st, err := store.NewStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, name := range []string{"audit.key", "enum.key", "deployment.key"} {
		if _, err := keyfile.LoadOrCreate(filepath.Join(configDir, name), 32); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configDir, "audit.state"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "audit"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "audit", "audit.log"), []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("canary", "in-the-wal"); err != nil {
		t.Fatal(err)
	}

	p, err := Collect(context.Background(), st, dataDir, configDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if p.ServiceName != AppName {
		t.Fatalf("service %q", p.ServiceName)
	}
	var db []byte
	for _, f := range p.Files {
		if f.Path == "kybookmarks.db" {
			db = f.Data
		}
	}
	if db == nil {
		t.Fatal("no database member")
	}
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := os.WriteFile(snap, db, 0600); err != nil {
		t.Fatal(err)
	}
	conn, err := sql.Open("sqlite", snap)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var v string
	if err := conn.QueryRow(`SELECT value FROM settings WHERE key = 'canary'`).Scan(&v); err != nil || v != "in-the-wal" {
		t.Fatalf("snapshot lost the WAL row: %v %q", err, v)
	}
}

func TestCollectRefusesWithoutAuditKey(t *testing.T) {
	dataDir := t.TempDir()
	st, _ := store.NewStore(dataDir)
	defer st.Close()
	if _, err := Collect(context.Background(), st, dataDir, filepath.Join(dataDir, "config"), "test"); err == nil {
		t.Fatal("a capsule without the audit key restores a server that refuses to start; Collect must refuse")
	}
}
```

```go
// internal/backup/drill_test.go
func TestChecksFailOnMissingDatabase(t *testing.T) {
	dir := t.TempDir()
	checks := Checks(recoveryclient.Payload{Files: []recoveryclient.File{{Path: "kybookmarks.db"}}})(dir)
	for _, c := range checks {
		if c.Name == "Database present: kybookmarks.db" && !c.Passed {
			return
		}
	}
	t.Fatal("missing database was not reported")
}

func TestDrillRootIsUnderTheDataDir(t *testing.T) {
	if DrillRoot("/srv/data") != "/srv/data/drill" {
		t.Fatal(DrillRoot("/srv/data"))
	}
}
```

- [ ] **Step 2: Run red**

Run: `go test ./internal/backup/`
Expected: FAIL (no package).

- [ ] **Step 3: backup.go**

```go
// Package backup is what is specific to KyBookmarks in the suite's backup contract: what a
// capsule carries, how the drill judges a restore, and the adapters that bind this store
// and this deployment key to ky-primitives/recoveryclient. Pairing, key pin, schedule,
// local copies, deposit, drill mechanics and restore are the lib's.
package backup

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kybookmarks-server/internal/store"
)

// AppName is the service name KyRecovery pins at pairing; every capsule must carry it.
const AppName = "KyBookmarks"

const tokenLabel = "kybookmarks:setting:kyrecovery_token"

type settings struct{ s *store.Store }

func Settings(s *store.Store) recoveryclient.Settings { return settings{s} }

func (a settings) Get(key string) (string, error) {
	v, err := a.s.GetSetting(key)
	if errors.Is(err, store.ErrNotFound) {
		return "", recoveryclient.ErrNotFound
	}
	return v, err
}
func (a settings) Set(key, value string) error { return a.s.SetSetting(key, value) }
func (a settings) Delete(key string) error     { return a.s.DeleteSetting(key) }

// NewSealer seals the KyRecovery token under the deployment key, domain-separated so a row
// copied from another setting will not open.
func NewSealer(deploymentKey []byte) (recoveryclient.Sealer, error) {
	return recoveryclient.NewAESGCMSealer(deploymentKey, tokenLabel)
}

func RunConfig(dataDir, backupDir string, keep int, appVersion string, sealer recoveryclient.Sealer) recoveryclient.RunConfig {
	return recoveryclient.RunConfig{DataDir: dataDir, AppName: AppName, AppVersion: appVersion,
		BackupDir: backupDir, Keep: keep, Sealer: sealer}
}

// AuditDetails flattens the lib's details into the audit line: sorted keys, bounded,
// printable. The audit chain stores one string.
func AuditDetails(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%v", k, m[k])
	}
	return recoveryclient.AuditSafe(b.String())
}

// DrillRoot is under the data directory, never the system temp dir: the opened payload is
// the whole instance in the clear.
func DrillRoot(dataDir string) string { return filepath.Join(dataDir, "drill") }
```

- [ ] **Step 4: payload.go**

```go
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kybookmarks-server/internal/store"
)

const (
	dbMember       = "kybookmarks.db"
	auditLogMember = "audit/audit.log"
	manifestMember = "manifest.json"
)

// required are the CONFIG_DIR files a restore cannot start without: the audit chain key and
// mark, the decoy-salt key, and the deployment key that opens the stored KyRecovery token.
var required = []string{"audit.key", "audit.state", "enum.key", "deployment.key"}

// optional ride along when present: SSO settings (hold the client secret) and the pinned key.
var optional = []string{"sso.json"}

// Members lists what a capsule carries, in Collect's order, so the screen can say so
// without sealing anything.
func Members(dataDir, configDir string) []string {
	m := []string{dbMember}
	for _, f := range required {
		m = append(m, "config/"+f)
	}
	for _, f := range optional {
		if _, err := os.Stat(filepath.Join(configDir, f)); err == nil {
			m = append(m, "config/"+f)
		}
	}
	if _, err := os.Stat(recoveryclient.RecoveryKeyPath(dataDir)); err == nil {
		m = append(m, "recovery.pub")
	}
	return append(m, auditLogMember, manifestMember)
}

// Collect gathers everything a restore needs. A missing required key is fatal: a capsule that
// restores a server that refuses to start is worse than no capsule, because the drill passes.
func Collect(ctx context.Context, st *store.Store, dataDir, configDir, appVersion string) (recoveryclient.Payload, error) {
	var files []recoveryclient.File

	scratch, err := os.MkdirTemp(dataDir, "snapshot-*")
	if err != nil {
		return recoveryclient.Payload{}, err
	}
	defer os.RemoveAll(scratch)
	snap := filepath.Join(scratch, dbMember)
	if err := recoveryclient.SQLiteSnapshot(ctx, st.DB(), snap); err != nil {
		return recoveryclient.Payload{}, fmt.Errorf("database snapshot: %w", err)
	}
	db, err := os.ReadFile(snap)
	if err != nil || len(db) == 0 {
		return recoveryclient.Payload{}, errors.New("database snapshot is empty")
	}
	files = append(files, recoveryclient.File{Path: dbMember, Data: db, Mode: 0600})

	for _, name := range required {
		b, err := os.ReadFile(filepath.Join(configDir, name))
		if err != nil || len(b) == 0 {
			return recoveryclient.Payload{}, fmt.Errorf("backup requires %s: %w", name, err)
		}
		files = append(files, recoveryclient.File{Path: "config/" + name, Data: b, Mode: 0600})
	}
	for _, name := range optional {
		if b, err := os.ReadFile(filepath.Join(configDir, name)); err == nil {
			files = append(files, recoveryclient.File{Path: "config/" + name, Data: b, Mode: 0600})
		}
	}
	if pub, err := os.ReadFile(recoveryclient.RecoveryKeyPath(dataDir)); err == nil {
		files = append(files, recoveryclient.File{Path: "recovery.pub", Data: pub, Mode: 0600})
	}
	auditLog, err := os.ReadFile(filepath.Join(dataDir, "audit", "audit.log"))
	if err != nil {
		return recoveryclient.Payload{}, fmt.Errorf("backup requires the audit log: %w", err)
	}
	files = append(files, recoveryclient.File{Path: auditLogMember, Data: auditLog, Mode: 0600})

	manifest, _ := json.Marshal(map[string]any{
		"service": AppName, "app_version": appVersion,
		"restore": "kybookmarks-server restore -capsule <file> -to <dir>; DATA_DIR gets kybookmarks.db, audit/, recovery.pub; CONFIG_DIR gets config/*",
	})
	files = append(files, recoveryclient.File{Path: manifestMember, Data: manifest, Mode: 0600})

	return recoveryclient.Payload{
		ServiceName: AppName, AppVersion: appVersion, Files: files,
		Dependencies:       map[string]any{"sqlite": "modernc.org/sqlite", "go": "1.26"},
		VerificationRecipe: map[string]any{"required_tables": []string{"accounts", "vault_objects", "settings"}, "require_any_admin": true},
	}, nil
}
```

- [ ] **Step 5: drill.go**

```go
package backup

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Busness-app/ky-primitives/recoveryclient"
)

// Checks judge an opened capsule: every member present, the database passes integrity_check,
// the required tables exist, and at least one active admin can log in afterwards.
func Checks(payload recoveryclient.Payload) func(dir string) []recoveryclient.Check {
	return func(dir string) []recoveryclient.Check {
		var out []recoveryclient.Check
		add := func(name string, ok bool, msg string) {
			out = append(out, recoveryclient.Check{Name: name, Passed: ok, Message: msg})
		}
		for _, f := range payload.Files {
			_, err := os.Stat(filepath.Join(dir, f.Path))
			label := "Member present: " + f.Path
			if f.Path == dbMember {
				label = "Database present: " + dbMember
			}
			add(label, err == nil, errText(err))
		}
		db, err := sql.Open("sqlite", filepath.Join(dir, dbMember)+"?mode=ro")
		if err != nil {
			add("Database opens", false, err.Error())
			return out
		}
		defer db.Close()
		var integrity string
		err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
		add("Database integrity", err == nil && integrity == "ok", integrity+errText(err))
		for _, table := range []string{"accounts", "vault_objects", "settings"} {
			var n int
			err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n)
			add("Table present: "+table, err == nil && n == 1, errText(err))
		}
		var admins int
		err = db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE role='admin' AND status='active'`).Scan(&admins)
		add("Active administrator", err == nil && admins > 0, fmt.Sprintf("%d active administrator(s)%s", admins, errText(err)))
		return out
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
```

Import `_ "modernc.org/sqlite"` in `drill.go` (the store already registers it, but this package must not depend on that).

- [ ] **Step 6: Green, commit**

Run: `go vet ./internal/backup/ && go test -race ./internal/backup/`
Expected: PASS.

```bash
git add internal/backup
git commit -m "backup: adapters over ky-primitives/recoveryclient; collector and drill checks"
```

---

### Task 3: Handlers and routes

**Files:**
- Create: `internal/api/backup_handlers.go`, `internal/api/backup_test.go`
- Modify: `internal/api/server.go` (fields, `NewServer`, routes), `internal/api/access_test.go` (admin-only cases)

**Interfaces:**
- Consumes: Task 2; `recoveryclient.{NewClient,Options,ValidateURL,ParsePinRequest,StoreRecoveryKey,LoadRecoveryKey,StorePairing,ClearPairing,HasPairing,LoadPairing,LastDeposit,ListLocalCopies,Interval,SetInterval,NextRun,Run,Outcome,Drill,Seal,FilenameSafe,AuditSafe,MinInterval}` and errors `ErrNotPaired, ErrKeyMismatch, ErrKeyPinMissing, ErrNoDestination, ErrInProgress, ErrRemote, ErrReceiptUnrecorded, ErrBadInterval`; `capsule.ErrCapsuleTooLarge`.
- Produces routes, all `withAdmin`:

| Method | Path | Handler | Response |
|---|---|---|---|
| POST | /api/admin/backup/drill | handleBackupDrill | `recoveryclient.DrillResult` |
| POST | /api/admin/backup/export-capsule | handleExportCapsule | `.kycap` attachment; CSRF required |
| POST | /api/admin/backup/pair-remote | handlePairRemote | `{recovery_key_id, threshold, total_shares}` |
| POST | /api/admin/backup/deposit | handleRunBackup | `recoveryclient.Result` |
| DELETE | /api/admin/backup/pairing | handleUnpair | `{paired:false}` |
| POST | /api/admin/backup/pin-key | handlePinKey | `{recovery_key_id, threshold, total_shares}` |
| PUT | /api/admin/backup/schedule | handleSetSchedule | `{interval_sec}` |
| GET | /api/admin/backup/status | handleBackupStatus | status object |

Status fields: `paired, key_pinned, app_name, app_version, recovery_url, recovery_key_id, threshold, total_shares, recovery_key_error, last_deposit, local_dir, local_keep, local_copies, local_error, interval_sec, min_interval_sec, next_run_at, allow_private_recovery, members`.

- [ ] **Step 1: Failing handler tests**

`internal/api/backup_test.go`. Helpers: `setupTestServer` from `api_test.go`; obtain an admin session and CSRF cookie the way `pairing_test.go` does (`/api/setup` then login). Add a `withBackupDir(t, srv, dir)` that sets `srv.cfg.Backup.Dir` and a fake depositor:

```go
type fakeRecovery struct{ receipt recoveryclient.Receipt; err error; got []byte }

func (f *fakeRecovery) ClaimPairing(context.Context, string, string, string, string) (recoveryclient.PairingResult, error) {
	return recoveryclient.PairingResult{}, errors.New("not in this test")
}
func (f *fakeRecovery) Deposit(_ context.Context, _, _ string, c []byte) (recoveryclient.Receipt, error) {
	f.got = c
	return f.receipt, f.err
}

// freshPin mints a throwaway suite key and returns its public half as the pin-key route
// takes it. The private half is dropped here; the tests never open a capsule.
func freshPin(t *testing.T) (publicB64 string) {
	t.Helper()
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Public().Bytes())
}
```

Tests:

```go
func TestPinKeyIsWriteOnce(t *testing.T)                 // pin A → 200; pin B → 409; pin A again → 200
func TestPinKeyBadTopology(t *testing.T)                 // 1-of-3 → 400
func TestRunWithPinnedKeyAndNoDestination(t *testing.T)  // pin, POST deposit → 412, body mentions KYBOOKMARKS_BACKUP_DIR
func TestRunWritesLocalCopy0600(t *testing.T)            // Backup.Dir set, pin, POST deposit → 200; one *.kycap at 0600; audit has admin.backup_run
func TestUnpairKeepsPin(t *testing.T)                    // seed a pairing via recoveryclient.StorePairing with the test sealer; DELETE pairing → 200; status key_pinned true, paired false; DELETE again → 412
func TestScheduleBounds(t *testing.T)                    // 0 ok, 899 → 400, 1<<55 → 400, 900 ok; audit details carry interval_sec=900
func TestStatusNeverCarriesToken(t *testing.T)           // pairing seeded; status body has no "kyrecovery_token_enc" and not the token
func TestExportCapsuleUnpairedIs412(t *testing.T)
func TestBackupRoutesRequireAdmin(t *testing.T)          // each route with a user session → 403, none → 401
```

- [ ] **Step 2: Run red**

Run: `go test ./internal/api/ -run 'PinKey|RunWith|LocalCopy|Unpair|Schedule|Status|ExportCapsule|BackupRoutes'`
Expected: FAIL (build).

- [ ] **Step 3: Write backup_handlers.go**

Port `kysignon-server/internal/api/backup_handlers.go` handler by handler. The mapping:

- `h.cfg.DataDir` → `s.cfg.DataDir`; `h.store` (settings) → `backup.Settings(s.store)`; `backup.X` (kysignon's package) → `recoveryclient.X`; `config.MinBackupDepositInterval` → `recoveryclient.MinInterval`; `h.cfg.BackupDir/BackupKeep/BackupAllowPrivateRecovery` → `s.cfg.Backup.Dir/Keep/AllowPrivateRecovery`; `h.record(r, action, actorID, actorName, targetID, outcome, details)` → `s.auditEvent(r, action, actorID, "", backup.AuditDetails(details)+" outcome="+outcome)`; `requestGrant`/step-up → nothing (admin role + CSRF from `withAdmin`).
- `s.recovery` is a `recoveryClient` interface (`ClaimPairing` + `recoveryclient.Depositor`) set in `NewServer` to `recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.Backup.AllowPrivateRecovery})`; tests swap it for `fakeRecovery`.
- `s.sealer` built once in `NewServer` with `backup.NewSealer(cfg.DeploymentKey)`; a nil deployment key (tests) gets `bytes.Repeat([]byte{7}, 32)` from `setupTestServer`.

Shape of the run handler, which every other one follows:

```go
func (s *Server) handleRunBackup(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.currentUser(r)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 16*time.Minute)
	defer cancel()
	rc := backup.RunConfig(s.cfg.DataDir, s.cfg.Backup.Dir, s.cfg.Backup.Keep, s.cfg.AppVersion, s.sealer)
	res, err := recoveryclient.Run(ctx, rc, backup.Settings(s.store), func() (recoveryclient.Payload, error) {
		return backup.Collect(ctx, s.store, s.cfg.DataDir, s.cfg.ConfigDir, s.cfg.AppVersion)
	}, s.recovery)
	action, outcome, details := recoveryclient.Outcome(res, err)
	s.auditEvent(r, action, acc.ID, "", backup.AuditDetails(details)+" outcome="+outcome)
	switch {
	case err == nil, errors.Is(err, recoveryclient.ErrReceiptUnrecorded):
		writeJSON(w, http.StatusOK, res)
	case errors.Is(err, recoveryclient.ErrNotPaired):
		http.Error(w, `{"error":"no_recovery_key","message":"No recovery key; pair with KyRecovery or pin the suite key by hand"}`, http.StatusPreconditionFailed)
	case errors.Is(err, recoveryclient.ErrNoDestination):
		http.Error(w, `{"error":"no_destination","message":"Nowhere to put a capsule: pair with KyRecovery or set KYBOOKMARKS_BACKUP_DIR"}`, http.StatusPreconditionFailed)
	case errors.Is(err, recoveryclient.ErrKeyPinMissing):
		http.Error(w, `{"error":"key_pin_missing","message":"Paired, but recovery.pub is missing or does not match the pin"}`, http.StatusPreconditionFailed)
	case errors.Is(err, recoveryclient.ErrInProgress), errors.Is(err, recoveryclient.ErrKeyMismatch):
		http.Error(w, `{"error":"conflict"}`, http.StatusConflict)
	case errors.Is(err, capsule.ErrCapsuleTooLarge):
		http.Error(w, `{"error":"too_large"}`, http.StatusRequestEntityTooLarge)
	case errors.Is(err, recoveryclient.ErrRemote):
		http.Error(w, `{"error":"kyrecovery","message":"`+recoveryclient.AuditSafe(err.Error())+`"}`, http.StatusBadGateway)
	default:
		http.Error(w, `{"error":"backup_failed"}`, http.StatusInternalServerError)
	}
}
```

`handlePairRemote`: `recoveryclient.ValidateURL(req.RecoveryURL, s.cfg.Backup.AllowPrivateRecovery)` first (400; when the error mentions private, the message names `KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY`); `ClaimPairing(ctx, url, code, backup.AppName, backup.AppName)`; `StoreRecoveryKey` (`fs.ErrExist` → 409); `StorePairing(settings, s.sealer, url, token)`; audit `admin.backup_paired` with `recovery_key_id` and `allow_private`.

`handleExportCapsule`: `LoadRecoveryKey` (`ErrNotPaired` → 412, `ErrKeyMismatch` → 409); `Collect`; `recoveryclient.Seal`; audit `admin.backup_exported` **before** writing the body and refuse with 500 if the audit write fails (spec: an export that cannot be audited is refused); `Content-Disposition: attachment; filename="KyBookmarks-<FilenameSafe(id)>.kycap"`.

`handleBackupDrill`: `Collect` then `recoveryclient.Drill(ctx, backup.DrillRoot(s.cfg.DataDir), payload, backup.Checks(payload))`; audit `admin.backup_drill` with `passed`.

`handleUnpair`, `handlePinKey`, `handleSetSchedule`, `handleBackupStatus`: copy kysignon's bodies (`backup_handlers.go:301-460`) with the mapping above. `handleBackupStatus` adds `members: backup.Members(dataDir, configDir)`.

`server.go` routes:

```go
	mux.HandleFunc("POST /api/admin/backup/drill", s.withAdmin(s.handleBackupDrill))
mux.HandleFunc("POST /api/admin/backup/export-capsule", s.withAdmin(s.handleExportCapsule))
	mux.HandleFunc("POST /api/admin/backup/pair-remote", s.withAdmin(s.handlePairRemote))
	mux.HandleFunc("POST /api/admin/backup/deposit", s.withAdmin(s.handleRunBackup))
	mux.HandleFunc("DELETE /api/admin/backup/pairing", s.withAdmin(s.handleUnpair))
	mux.HandleFunc("POST /api/admin/backup/pin-key", s.withAdmin(s.handlePinKey))
	mux.HandleFunc("PUT /api/admin/backup/schedule", s.withAdmin(s.handleSetSchedule))
	mux.HandleFunc("GET /api/admin/backup/status", s.withAdmin(s.handleBackupStatus))
```

- [ ] **Step 4: Green, commit**

Run: `go test -race ./internal/api/`
Expected: PASS.

```bash
git add internal/api
git commit -m "api: backup routes to the KySignOn spec"
```

---

### Task 4: `cmd/server`: dispatcher, loop, deposit, restore

**Files:**
- Modify: `cmd/server/main.go`
- Create: `cmd/server/backup.go`, `cmd/server/restore_test.go`

- [ ] **Step 1: Failing test**

```go
// cmd/server/restore_test.go
func TestRestoreRefusesWrongServiceBeforeReadingShares(t *testing.T) {
	// Seal a payload for "Other" to a throwaway key, write it to a file, call restore with
	// expectService "KyBookmarks" and no shares; must fail mentioning the service, and must
	// not mention shares.
}
```

Fill it with `recoverykey` + `recoveryclient.Seal` as `ky-primitives/recoveryclient/restore_test.go` does; copy its fixture code.

- [ ] **Step 2: Dispatcher**

Top of `main`:

```go
func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
		case "backup-drill":
			runBackupDrill()
			return
		case "export-capsule":
			runExportCapsule(argOr(2, "KyBookmarks.kycap"))
			return
		case "deposit":
			runDeposit()
			return
		case "restore":
			runRestore(os.Args[2:])
			return
		default:
			fmt.Fprintf(os.Stderr, "usage: kybookmarks-server [serve|backup-drill|export-capsule <out>|deposit|restore -capsule <file> -to <dir> [-service <name>]]\n")
			os.Exit(2)
		}
	}
	serve()
}
```

Move the current body of `main` into `serve()`. `argOr(i int, def string) string` returns `os.Args[i]` when present.

- [ ] **Step 3: backup.go**

```go
// openForBackup opens the store and reads the same env as serve, without listening.
func openForBackup() (*store.Store, api.Config) { /* DATA_DIR, CONFIG_DIR, loadBackupConfig, deployment key, appVersion */ }

func runBackupDrill() {
	st, cfg := openForBackup()
	defer st.Close()
	ctx := context.Background()
	payload, err := backup.Collect(ctx, st, cfg.DataDir, cfg.ConfigDir, cfg.AppVersion)
	if err != nil {
		log.Fatalf("collect: %v", err)
	}
	res, err := recoveryclient.Drill(ctx, backup.DrillRoot(cfg.DataDir), payload, backup.Checks(payload))
	if err != nil {
		log.Fatalf("drill: %v", err)
	}
	for _, c := range res.Checks {
		fmt.Printf("%-5t %s %s\n", c.Passed, c.Name, c.Message)
	}
	if !res.Passed {
		os.Exit(1)
	}
}

func runExportCapsule(out string) { /* LoadRecoveryKey, Collect, Seal, os.WriteFile(out, raw, 0600); print id + size; never the key */ }

func runDeposit() {
	st, cfg := openForBackup()
	defer st.Close()
	res, err := runOnce(context.Background(), st, cfg, recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.Backup.AllowPrivateRecovery}))
	recordRun(st, cfg, "cli", res, err)
	if err != nil {
		os.Exit(1)
	}
}

func runOnce(ctx context.Context, st *store.Store, cfg api.Config, client recoveryclient.Depositor) (recoveryclient.Result, error) {
	sealer, err := backup.NewSealer(cfg.DeploymentKey)
	if err != nil {
		return recoveryclient.Result{}, err
	}
	rc := backup.RunConfig(cfg.DataDir, cfg.Backup.Dir, cfg.Backup.Keep, cfg.AppVersion, sealer)
	return recoveryclient.Run(ctx, rc, backup.Settings(st), func() (recoveryclient.Payload, error) {
		return backup.Collect(ctx, st, cfg.DataDir, cfg.ConfigDir, cfg.AppVersion)
	}, client)
}

func recordRun(auditLogger *audit.Logger, actor string, res recoveryclient.Result, err error) {
	action, outcome, details := recoveryclient.Outcome(res, err)
	_, _ = auditLogger.Log(context.Background(), action, actor, "", "", backup.AuditDetails(details)+" outcome="+outcome)
	if err != nil {
		log.Printf("backup (%s): %s", actor, recoveryclient.AuditSafe(err.Error()))
		return
	}
	log.Printf("backup (%s): capsule %s (%d bytes) local=%q deposited=%t", actor, res.Manifest.CapsuleID, res.SizeBytes, res.LocalPath, res.Receipt != nil)
}

// backupLoop polls the admin's schedule once a minute; a change in the UI needs no restart.
// The wait honours shutdown; the run does not, so SIGTERM cannot land between KyRecovery
// storing a capsule and the receipt being written.
func backupLoop(ctx context.Context, st *store.Store, cfg api.Config, auditLogger *audit.Logger) {
	client := recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.Backup.AllowPrivateRecovery})
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		next, on, err := recoveryclient.NextRun(cfg.Backup.DepositInterval, backup.Settings(st))
		if err != nil {
			log.Printf("backup: schedule unreadable: %s", recoveryclient.AuditSafe(err.Error()))
			continue
		}
		if !on || time.Now().Before(next) {
			continue
		}
		runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 16*time.Minute)
		res, err := runOnce(runCtx, st, cfg, client)
		cancel()
		if errors.Is(err, recoveryclient.ErrNotPaired) || errors.Is(err, recoveryclient.ErrNoDestination) {
			continue // never configured; silence is correct only here
		}
		recordRun(auditLogger, "system", res, err)
	}
}

func runRestore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	capsulePath := fs.String("capsule", "", "path to the .kycap file")
	to := fs.String("to", "", "empty directory to restore into")
	service := fs.String("service", backup.AppName, "expected service name in the manifest")
	_ = fs.Parse(args)
	if *capsulePath == "" || *to == "" {
		fs.Usage()
		os.Exit(2)
	}
	shares, err := recoveryclient.ReadShares(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	if err := restore(*capsulePath, *to, *service, shares, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// restore is the one function in this server allowed to open a capsule sealed to the suite
// key; nodecrypt_test.go pins that.
func restore(capsulePath, targetDir, expectService string, shares []string, stdout io.Writer) error {
	return recoveryclient.Restore(capsulePath, targetDir, expectService, shares, stdout)
}
```

`serve()`: create a root context cancelled on SIGINT/SIGTERM and `go backupLoop(ctx, dbStore, cfg, auditLogger)` before `ListenAndServe`. Fix `recordRun`'s signature so both call sites pass the audit logger (the CLI opens one with the same `audit.NewLogger` call `serve` uses).

- [ ] **Step 4: Green, commit**

Run: `go vet ./... && go test -race ./cmd/... && go build -o /tmp/kyb ./cmd/server && /tmp/kyb restore 2>&1 | head -2`
Expected: tests PASS; the binary prints usage for `restore` without flags.

```bash
git add cmd/server
git commit -m "server: subcommands, minute-polling backup loop, restore via recoveryclient"
```

---

### Task 5: Backup tab in the admin panel

**Files:**
- Create: `frontend/src/pages/AdminBackup.tsx` (port of kysignon `web/src/components/AdminBackup.tsx`, 586 lines)
- Modify: `frontend/src/pages/AdminPanel.tsx:21,162-186` (fourth tab `backup`)
- Modify: `frontend/src/index.css` (copy the `.dr-*` rules from kysignon `web/src/index.css`)

- [ ] **Step 1: Port the component**

Copy `AdminBackup.tsx`; then: `secureFetch` → `getJSON/postJSON/putJSON/deleteJSON` from `../lib/api` (all four already exist at `api.ts:49-54`); paths `/api/admin/backup/*` stay; delete the `requestGrant` step-up prompt and its imports; `KYSIGNON_BACKUP_DIR` → `KYBOOKMARKS_BACKUP_DIR`; the "what a capsule carries" list reads `status.members`. Keep: four fact cards (key, KyRecovery, local copies, schedule), one action row (Back up now, Download capsule, Run drill), schedule form (minutes → `interval_sec`, off = 0, min from `min_interval_sec`), pairing panel with Unpair, key-by-hand panel, warnings for no key, no destination, schedule off. Unpair copy: "Removes the URL and sealed token rows. The key pin, receipts and local copies stay. The credential is dead only when the KyRecovery admin revokes it."

Download capsule: use an authenticated POST/blob request to `/api/admin/backup/export-capsule`; `withAdmin` applies the CSRF header before the server collects and seals the payload.

- [ ] **Step 2: Tab**

`AdminPanel.tsx`: `useState<'users' | 'sso' | 'audit' | 'backup'>`; a fourth button with a `HardDriveDownload` icon from `lucide-react` and label "Backup & Recovery"; `{activeTab === 'backup' && <AdminBackup />}`.

- [ ] **Step 3: Build and click through**

Run: `cd frontend && npm run build`
Then, with a throwaway data dir and `KYBOOKMARKS_BACKUP_DIR` set: log in as admin, open the tab, pin a fresh key by hand (`recoverykey.Generate()` then `base64.StdEncoding.EncodeToString(k.Public().Bytes())` in a ten-line Go test), Back up now, see the local copy count rise, Run drill, set the schedule to 15 minutes and see `next_run_at`. Screenshot for the PR.

- [ ] **Step 4: Commit**

```bash
git add frontend/src
git commit -m "frontend: Backup & Recovery tab to the KySignOn spec"
```

---

### Task 6: Decrypt guard, compose, Dockerfile, ablation

**Files:**
- Create: `internal/backup/nodecrypt_test.go`, `docker-compose.lan-dns.yml`
- Modify: `docker-compose.yml`, `Dockerfile:36`, `scripts/ablate.py`

- [ ] **Step 1: Guard**

```go
package backup_test

import (
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient/guardtest"
)

func TestNothingInTheServerDecrypts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	guardtest.NoDecryptOutside(t, root, map[string][]string{
		filepath.Join("cmd", "server", "backup.go"): {"restore"},
	})
}
```

Prove it: add `_ = recoveryclient.Restore` inside `handleBackupStatus`, run `go test ./internal/backup/ -run Nothing`, confirm it fails naming `backup_handlers.go`, remove, confirm pass. Paste both outputs in the PR.

- [ ] **Step 2: Compose and Dockerfile**

`docker-compose.yml` environment: add

```yaml
      # Sealed backups. Empty dir = no local copies; pair with KyRecovery or set this.
      KYBOOKMARKS_BACKUP_DIR: ${KYBOOKMARKS_BACKUP_DIR:-}
      KYBOOKMARKS_BACKUP_KEEP: ${KYBOOKMARKS_BACKUP_KEEP:-7}
      # Default schedule only; the admin sets the live one in the Backup tab.
      KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL: ${KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL:-24h}
      # Off: a KyRecovery on a private or CGNAT address is refused. HTTPS is always required.
      KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY: ${KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY:-false}
      # KYBOOKMARKS_DNS lives only in docker-compose.lan-dns.yml.
```

and a `kybookmarks_backups:/app/backups` volume with a comment that it is used only when `KYBOOKMARKS_BACKUP_DIR=/app/backups`. `Dockerfile:36`: `mkdir -p /app/data /app/config /app/backups` and chown all three.

`docker-compose.lan-dns.yml`:

```yaml
# Optional override: send the container's DNS lookups to your LAN's resolver, so names that
# exist only there (a KyRecovery behind your own proxy) resolve inside the container.
#
#   KYBOOKMARKS_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d
services:
  kybookmarks-server:
    dns:
      - ${KYBOOKMARKS_DNS:?set KYBOOKMARKS_DNS to your LAN DNS server}
```

- [ ] **Step 3: Ablation**

Add to `scripts/ablate.py` (target file `internal/api/backup_handlers.go`, add a `BACKUPH` constant):

```python
 ("export capsule not audited", BACKUPH, "TestExportCapsule",
  "<the exact audit line before the body write>",
  "<the same line commented out>"),
 ("unpair also drops the key pin", BACKUPH, "TestUnpairKeepsPin",
  "\tif err := recoveryclient.ClearPairing(settings); err != nil {",
  "\t_ = settings.Delete(\"kyrecovery_key_id\")\n\tif err := recoveryclient.ClearPairing(settings); err != nil {"),
```

Fill the first pair with the real lines once the handler exists; add `TestExportCapsuleIsRefusedWhenAuditFails` to `backup_test.go` (make the audit logger's store read-only the way `TestAuditWriteFailureIsNotSilent` does) so the ablation has a test to catch it.

Run: `python3 scripts/ablate.py && docker compose config -q && KYBOOKMARKS_DNS=1.1.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml config -q`
Expected: all caught, both configs valid.

- [ ] **Step 4: Commit**

```bash
git add internal/backup/nodecrypt_test.go internal/api/backup_test.go docker-compose.yml docker-compose.lan-dns.yml Dockerfile scripts/ablate.py
git commit -m "guard via guardtest; compose backup env and LAN DNS override; ablations"
```

---

### Task 7: Runbook, README, AGENTS

**Files:**
- Create: `docs/RESTORE.md` (from `kysignon-server/docs/RESTORE.md`), `README.md`
- Modify: `AGENTS.md` (capabilities, env table, DOX index)

- [ ] **Step 1: RESTORE.md**

Adapt kysignon's runbook. Binary: `kybookmarks-server restore -capsule <file> -to <dir> [-service KyBookmarks]`, shares on stdin. What comes out: `kybookmarks.db`, `audit/audit.log`, `recovery.pub`, `config/{audit.key,audit.state,enum.key,deployment.key,sso.json}`, `manifest.json`. Put `config/*` into the `CONFIG_DIR` volume and the rest into `DATA_DIR`. Keep every hazard: empty-volume gate (a restored `kybookmarks.db` next to a stale `-wal` replays the wrong log), copy the old volumes out first at mode 700 verified by file count, no keys on stdout, Docker target writable as `$(id -u):$(id -g)`. Rotation: `audit.key` is never rotated by hand (the chain is keyed to it; a new key forks the chain), `enum.key` may be regenerated (only the decoy salt changes), `deployment.key` may be regenerated only together with a re-pair (it seals the KyRecovery token and nothing else), `SYNC_SECRET` must be re-issued from KySignOn, `sso.json`'s client secret rotated in KySignOn. Sessions: `DELETE FROM sessions` revokes everything at once (this product has a single sessions table). Post-restore trust step: compare `recovery_key_id` in the Backup tab against the ceremony card.

- [ ] **Step 2: Prove Step 1 of the runbook**

Generate a 2-of-3 key with a ten-line Go test: `k, _ := recoverykey.Generate()`, `shares, _ := recoverykey.Split(k, 2, 3)`, print each share with `shares[i].String()` and `base64.StdEncoding.EncodeToString(k.Public().Bytes())`; pin it through `POST /api/admin/backup/pin-key` against a throwaway data dir with `KYBOOKMARKS_BACKUP_DIR` set, `POST /api/admin/backup/deposit`, then:

```bash
printf '%s\n%s\n' "$SHARE1" "$SHARE2" | ./kybookmarks-server restore -capsule "$KYBOOKMARKS_BACKUP_DIR"/*.kycap -to /tmp/restore-test
```

Also each failure mode: one share (error names the threshold), `-service Other` (refused before shares are read), non-empty `-to` (refused). Record the four outputs in the PR.

- [ ] **Step 3: README.md and AGENTS.md**

`README.md` (new; the repo has none): what KyBookmarks is in two sentences, then "Disaster recovery": what a capsule carries; why TLS matters when the capsule is sealed (the public key arrives at pairing, trust on first use; the token; the receipts); pin by hand or compare fingerprints before trusting a pairing; every env var from Global Constraints with default and meaning; the LAN DNS override command; link to `docs/RESTORE.md`.

`AGENTS.md`: capability 8 "KyRecovery backups" in one paragraph; env table rows for the five variables and `deployment.key`; the step-up note ("admin role + CSRF is this product's step-up equivalent for backup routes"); DOX index entries for `internal/backup`, `docs/RESTORE.md`, `README.md`; replace the plan pointer bullet written by the first plan.

- [ ] **Step 4: Commit, PR**

```bash
git add docs/RESTORE.md README.md AGENTS.md
git commit -m "docs: restore runbook, README disaster recovery, DOX to spec"
```

Open one PR (`pull-request` skill). Body: guard proof outputs, runbook proof outputs, the step-up assumption, the screenshot. Expect a security review round.

---

### Task 8: Prove it live, hand off

- [ ] **Step 1: Screen live**

```bash
rm -rf /tmp/kyb && mkdir -p /tmp/kyb/data /tmp/kyb/config /tmp/kyb/backups
DATA_DIR=/tmp/kyb/data CONFIG_DIR=/tmp/kyb/config KYBOOKMARKS_BACKUP_DIR=/tmp/kyb/backups ./kybookmarks-server &
```

Set up an admin, pin a fresh key by hand, Back up now, `ls -l /tmp/kyb/backups` shows `KyBookmarks.<id>.kycap` at `-rw-------`, the Audit tab shows `admin.backup_key_pin` and `admin.backup_run`.

- [ ] **Step 2: Live pairing in the homelab**

```bash
KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY=true KYBOOKMARKS_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d --force-recreate
docker inspect KyBookmarks-Server --format '{{.HostConfig.Dns}}'   # must print [192.168.1.1]
```

Pair from the tab against Yoshi's KyRecovery, Back up now, confirm the receipt on the tab and the capsule in KyRecovery's dashboard. Unpair; status shows key pinned, not paired.

- [ ] **Step 3: Board**

Post to `kybookmarks-kyrecovery-deposit` (skill `myslop-handoff`): spec rows done, proof outputs, status `done`.

## Self-review notes

- Spec rows: 1 (T3 pair-remote), 2 (T3 pin-key), 3 (T2/T3/T4 Run), 4 (T1 config + lib), 5 (T3 schedule + T4 loop + T5 form), 6 (T3 unpair), 7 (T1 + T3 ValidateURL + startup log), 8 (T6), 9 (T5), 10 (T3 admin test, assumption noted), 11 (T6), 12 (T7), 13 (T7), 14 (done by the first plan).
- The lib's `Run` needs `Keep >= 1` and refuses at write time; `loadBackupConfig` refuses `Keep < 1` at startup so the first scheduled run is not where the operator learns it.
- `Collect` refuses without `audit.key`, `audit.state`, `enum.key`, `deployment.key`; on a fresh install all four exist after first boot (keyfile mints the three keys; `audit.state` is written by the first audit entry, which `/api/setup` produces). A drill before any audit entry fails on `audit.state`; the message says so.

## Careful

- `withAdmin` checks CSRF on POST/PUT/DELETE; the frontend must send `X-CSRF-Token` on every backup call, including the export download.
- The capsule caps in `capsule` are exported constants; a large `audit.log` can push a capsule past `MaxCapsuleFileBytes`. The 413 path exists; if it fires in the homelab, the answer is log rotation, not a bigger cap.
- Never HTML-escape a value inside an inline `on*=` handler; React props are fine, `dangerouslySetInnerHTML` is not.
- `settings` rows the lib writes: `kyrecovery_key_id, kyrecovery_threshold, kyrecovery_total_shares, kyrecovery_url, kyrecovery_token_enc, kyrecovery_last_deposit, backup_interval_sec, backup_last_attempt`. Status must never return `kyrecovery_token_enc`.
