# KyBookmark Server

KyBookmark Server is the zero-knowledge encrypted bookmark synchronization and management server for the KySecurity Suite of software (KySignOn, KyPost, KyPasswords, KyBookmarks, KyNotes).

## Core Capabilities & Responsibilities

1. **Zero-Knowledge End-to-End Encryption**: Bookmarks, notes, titles, and custom folder names are encrypted on trusted clients using Web Crypto (AES-256-GCM / PBKDF2). The server stores only opaque encrypted payloads, UUIDs, versions, parent relationships (max 5 depth), and 90-day tombstones. Login and paper-recovery secrets are derived in the browser with PBKDF2 and stored server-side as Argon2id (`ky-primitives/password`); the paper key itself never reaches the server.
2. **Deterministic Versioning & CAS Synchronization**: First-write-wins compare-and-swap concurrency. Failed concurrent writes are preserved for 90-day reconciliation rather than silently dropped.
3. **Netscape Bookmark HTML Import & Export**: Standard browser bookmark file parsing and export supporting top-level merging and folder trees up to 5 levels.
4. **KySignOn SSO & Account Replication**: Native OIDC PKCE single sign-on with automatic redirect URI resolution; ID tokens are verified by `ky-primitives/oidcverify` against the issuer's JWKS with a per-login nonce (the issuer must be HTTPS). The directory-sync webhook (`/api/sync/events`) is verified by `ky-primitives/syncauth`: signature, timestamp window, event-id replay guard, and a signed `user.created`, `user.updated`, or `user.deleted` type over the bare SCIM user body KySignOn emits.
5. **90s QR / PIN Device Pairing**: Ephemeral pairing flow (`/api/devices/pair/request`, `/api/devices/pair/approve`, `/api/devices/pair/redeem`) for trusted mobile and browser extensions.
6. **Tamper-Evident Audit Logging**: HMAC-SHA256 hash chained log trail with verification. The chain key is per-install and never a constant — see "Audit chain" below.
7. **Patina Look & Feel**: React + Vite interface with KySecurity Patina theme (`#0d0f14`, cyan `#4deeea`, `Space Grotesk`, `IBM Plex Mono`).
8. **KyRecovery Backups**: sealed `kycap/3` capsules through `ky-primitives/recoveryclient`: pair with KyRecovery or pin the suite key by hand, local copies in `KYBOOKMARKS_BACKUP_DIR`, an admin-set schedule, restore drill, and a `restore` subcommand. Every backup route, including the capsule export, is a CSRF-protected admin `POST`/`PUT`/`DELETE`; a GET never exports. See "KyRecovery backups" below and `docs/RESTORE.md`.

## Audit chain

`internal/audit` writes `DATA_DIR/audit/audit.log` and keeps its key and high-water mark
in `CONFIG_DIR`. The two must be separate volumes: a key stored beside the log it protects
proves nothing.

| Variable | Meaning |
|---|---|
| `CONFIG_DIR` | Holds `audit.key` and `audit.state`. Defaults to `./config`. |
| `AUDIT_KEY` | Optional. Exactly 32 bytes as hex (`openssl rand -hex 32`) or base64. A value that is set but malformed refuses to start. Unset means the server generates a key into `CONFIG_DIR/audit.key` (0600) on first run. |
| `HMAC_SECRET` | **Legacy verification only.** Entries written before the chain was keyed are chained with this; it is never used to write. Leave it set to whatever the deployment used previously, or unset to fall back to the published constant those entries actually used. |
| `SYNC_SECRET` | Signs the `/api/sync/events` directory webhook. **No default**: unset makes the endpoint reject every request. |
| `KYBOOKMARKS_BACKUP_DIR` | Directory for sealed local backup copies. Unset means none. |
| `KYBOOKMARKS_BACKUP_KEEP` | Local copies retained, default 7, at least 1. Refused at startup below 1. |
| `KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL` | Default schedule only (`24h`); the admin's setting wins. `0` off, floor `15m`. |
| `KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY` | Admit private and CGNAT KyRecovery destinations. HTTPS stays mandatory. Logged at startup and on the pairing audit row. |
| `deployment.key` | Minted into `CONFIG_DIR` by `keyfile` on first run. Seals the KyRecovery token at rest and nothing else. |

Rules for anyone touching this package:

- **Both on-disk keys (`audit.key`, `enum.key`) are read and minted through
  `ky-primitives/keyfile`.** Do not add a third reader.
- **No constant may ever key a written entry.** `legacyDefaultSecret` exists solely to
  verify `v: 0` records and must stay out of the write path.
- **Entries are versioned.** `v: 0` is the legacy public-key format; `v: 1` is keyed and
  includes the version in the hashed payload. `chainHash` is the only hash definition, so
  the write and verify paths cannot drift.
- **The legacy tail is anchored** by a single keyed `audit.rekeyed` marker, written only on
  a genuine first keying (state absent *and* every entry `v: 0`).
- **A missing `audit.state` is a boot failure, except when the log is entirely
  pre-conversion.** With the mark gone there is nothing left to compare the log against, so
  a truncated log and an intact one are the same file — the previous behaviour, starting
  anyway and having `VerifyChain` report it forever, was an alarm that stayed on whatever
  the log contained. `NewLogger` returns `ErrBrokenChain` naming both files, in the same
  words `kypassword-server` uses, and does not recreate the mark on its own. The accepted
  exception: if every entry is still `v: 0`, `converge` runs before the missing-mark check,
  re-mints the log under the audit key, and writes a fresh mark — a genuine first keying,
  and the store boots reporting healthy rather than refusing. Reaching this case needs
  write access to `configDir`, which already implies key access, so it sits outside this
  chain's threat model. The high-water mark never decreases.
- **A legacy log is re-minted only when the mark attests to it.** `converge` requires the
  same record count *and* the same tail hash before rewriting a log under the audit key.
  Verifying under `legacyHash` is not enough on its own: `v: 0` is keyed with
  `legacyDefaultSecret`, published in this repository, so anyone who can write `DATA_DIR`
  can author a chain that verifies as `v: 0`. The mark is the only input outside that
  directory, which is what makes it the thing to ask. The one case with no mark to ask is
  a genuine first run: every entry `v: 0` and no mark ever written.
- **Order writes: entry first, state second.** A crash between them under-counts by one,
  which fails open for the newest entry only. The reverse order raises a false truncation
  alarm on every interrupted write, and false alarms are how real alarms get ignored.
- **The audit write is not the caller's to cancel.** `Log` takes a `context.Context` for
  its values, then strips the cancellation with `context.WithoutCancel` and applies its
  own timeout. Handlers pass `r.Context()`, which dies when the client hangs up, so
  honouring it would put the record of what a client just did under that client's control:
  hang up after the handler has acted and the entry is never written. Never pass a caller's
  context straight to `auditchain.Append`.
- **Derive that context *after* `l.mu.Lock()`, never before.** `l.mu` is a plain mutex no
  context can interrupt, so a deadline started above it is spent waiting on it: a caller
  queued behind a hung store reaches `Append` with a dead context and discards its record.
  That is the same suppression, reached by load instead of by a hang-up.
- **`appendTimeout` bounds only the chain lock, not `persist`.** No context reaches
  `persist`, so a hung store hangs its caller until it unhangs. The deadline is sound only
  because `l.chain` is driven from exactly one call site, under `l.mu`, so the chain lock
  never contends. A second `Append` call site breaks that and is refused by
  `TestChainIsDrivenFromOneCallSite`.
- **A mark write that fails is reported, never rolled back.** The record is already on
  disk, so refusing the append would leave the chain behind the log and fork it on the next
  call. `Log` returns the error; the chain advances anyway.
- **A torn write cannot merge with the next record.** A record and its terminator go out
  in one `Write`, which is not a promise: a short write on a full disk, or a crash, leaves
  the file ending mid-record. `persist` therefore terminates an unterminated tail before
  appending, so a fragment stays a line of its own — undecodable, but inert, because a
  non-record changes no record count. Without this the next append was welded onto the
  fragment, the entry that landed was lost, and every later boot died accusing the operator
  of removing entries. Power loss was enough to reach it. Nothing is ever removed from the
  log to achieve this. A failed write also records the fragment on the running `Logger`,
  because the next append may come before any restart re-scans the file:
  `TestShortWriteLeavesATornTail` makes the kernel produce a real short write with
  `RLIMIT_FSIZE` and is the only test that reaches that path.
- **A short log is described, never diagnosed.** A line that does not decode leaves the
  parsed count below the mark exactly as a deleted record does. `scanLog` counts those
  lines and `recover` returns `ErrCorruptLog` when the log is short *and* holds them,
  saying so and naming both possibilities — a torn write or corrupted block, or records
  removed with damage left behind. It does not say which: an undecodable line is
  attacker-writable, so anyone who can shorten the log can also choose which of the two
  errors the operator reads. `ErrTruncated` means only that the log is short and every
  line decoded. Both are boot failures; only the wording and the remedy differ.
- **A failed audit write is never discarded.** `internal/api` routes all 28 call sites
  through `Server.auditEvent`, which on failure logs to stderr (per `LOGGING.md`) and
  increments a counter that flips `/api/health`'s `status` to `degraded`. The *count* is
  not in that body: an unauthenticated caller filling the disk would be reading its own
  progress meter. It does not fail the request: every call site logs after the action has
  already happened, so a 500 would neither undo it nor restore the record, and would invite
  a retry that repeats it. Health stays HTTP **200** while degraded — nothing in either
  deployment sheds a 503 from rotation, so it would only tell the healthcheck and the
  uptime poller that a full disk is an outage. `TestDegradedHealthStaysHTTP200` pins the
  status code. Never write `_, _ = s.audit.Log(...)`.
- **A mark behind the log is caught up; a mark ahead of it is fatal.** On start, every
  record past the mark is verified against the key and against its predecessor, then the
  mark advances to the log's tail — a config volume that was briefly unwritable recovers.
  A log *shorter* than the mark is truncation: `NewLogger` returns `ErrTruncated` and
  `cmd/server` exits, naming both files. This is a boot failure, not a warning. The check
  runs **above** the empty-log short-circuit, so a log emptied to zero bytes, filled with
  junk, or deleted outright is refused too — those read as no entries at all, which is the
  most truncated a log can be, and they must not get a gentler answer than a log truncated
  to one record.

`python3 scripts/ablate.py` re-runs the ablation suite: it breaks each defence in turn and
fails if any test still passes. Run it after changing `internal/audit` or the sync webhook.

## Passwords and the paper key

`internal/crypto.HashPassword` and `VerifyPassword` wrap `ky-primitives/password`
(Argon2id, RFC 9106 second profile, PHC-encoded). `AuthSalt` is the browser's PBKDF2
salt, not the server's; the server hash carries its own. The paper recovery key is
generated in the browser because it wraps the vault key, so `ky-primitives/recoverycode`
(server-side generation) does not apply here. The browser posts
`recoveryVerifier = PBKDF2(paperKey)` at enrolment and the same value as `recoverySecret`
at recovery; the server stores and checks it exactly like a password.

## OIDC transaction binding

The HttpOnly OIDC transaction cookie is HMAC-authenticated under the persistent server key.
State, PKCE verifier, optional account-link target, and nonce are one indivisible transaction;
the callback refuses the cookie before token exchange if any field was altered. Account linking
must never trust a caller-supplied user ID without that binding.

## KyRecovery backups

`internal/backup` holds only what is this product's: `Collect` (SQLite `VACUUM INTO` through
the live handle, the four `CONFIG_DIR` keys, `sso.json`, `recovery.pub`, the audit log, a
manifest), the drill `Checks`, the `Settings` adapter over the `settings` table, the `Sealer`
under `deployment.key` (label `kybookmarks:setting:kyrecovery_token`), and `AuditDetails`.
Pairing, key pin, schedule, local copies, deposit, drill mechanics and restore are
`ky-primitives/recoveryclient`; do not reimplement any of them here.

- Service name is `backup.AppName` (`KyBookmarks`) everywhere: the pairing claim, every
  manifest, local copy names.
- **Step-up:** this product has none. Admin role plus CSRF (`withAdmin`) is the equivalent for
  every `/api/admin/backup/*` route; `TestBackupRoutesRequireAdmin` pins it.
- An export that cannot be recorded on the audit chain is refused (`auditCritical`);
  `TestExportCapsuleIsRefusedWhenAuditFails` and the ablation pin it.
- Unpair deletes the URL and sealed token rows only; the key pin stays. `TestUnpairKeepsPin`
  and the ablation pin it.
- `Collect` refuses without `audit.key`, `audit.state`, `enum.key`, `deployment.key`. On a
  fresh install all four exist after the first audit entry, which `/api/setup` writes.
- The decrypt boundary is `cmd/server/backup.go: restore` and nothing else;
  `internal/backup/nodecrypt_test.go` walks the repo with `guardtest`.
- The backup loop starts unconditionally, polls the schedule setting every minute, and runs on
  a context that survives SIGTERM.

## Verification & Build Commands

- **Backend Unit & Integration Tests**: `go test -v ./...`
- **Frontend Production Build**: `cd frontend && npm run build`
- **Docker Production Image**: `docker build -t kybookmarks-server:latest .`
- **Audit Ablation Suite**: `python3 scripts/ablate.py`
- **Backup export regression**: `go test ./internal/api -run 'TestExportCapsule'`

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

# DOX framework

## Core Contract

- AGENTS.md files are binding contracts for their subtree.
- Read from root to nearest AGENTS.md before editing.
- The nearest AGENTS.md controls local details; parent docs keep global rules.

## Update After Editing

- Run a DOX pass for every meaningful change.
- Update nearest owning AGENTS.md when behavior, responsibilities, or verification changes.
- Keep Child DOX Index entries current and delete stale rules.

## User Preferences

- Best-effort 90-second keyword refresh policy (foreground cadence; background catch-up on resume).
- DOX hierarchy scope is app-only.

## Child DOX Index

- `frontend/src/lib/storage.ts`: manages the persistent IndexedDB `keys` vault on trusted devices
  to allow 1-click SSO access without typing a password; explicit "Forget This Device" controls
  clear stored secrets from browser storage.
- `internal/backup`: what a capsule carries and how the drill judges a restore; adapters over `ky-primitives/recoveryclient`. The suite contract is `kyrecovery-server/zero_code_pairing_handoff_spec.md` v2.0.0.
- `docs/RESTORE.md`: the operator runbook for restoring from a capsule with custodian shares, proven against the code.
- `README.md`: operator-facing run and disaster-recovery notes, every env var.
