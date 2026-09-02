# KyBookmark Server

KyBookmark Server is the zero-knowledge encrypted bookmark synchronization and management server for the KySecurity Suite of software (KySignOn, KyPost, KyPasswords, KyBookmarks, KyNotes).

## Core Capabilities & Responsibilities

1. **Zero-Knowledge End-to-End Encryption**: Bookmarks, notes, titles, and custom folder names are encrypted on trusted clients using Web Crypto (AES-256-GCM / PBKDF2). The server stores only opaque encrypted payloads, UUIDs, versions, parent relationships (max 5 depth), and 90-day tombstones.
2. **Deterministic Versioning & CAS Synchronization**: First-write-wins compare-and-swap concurrency. Failed concurrent writes are preserved for 90-day reconciliation rather than silently dropped.
3. **Netscape Bookmark HTML Import & Export**: Standard browser bookmark file parsing and export supporting top-level merging and folder trees up to 5 levels.
4. **KySignOn SSO & Account Replication**: Native OIDC PKCE single sign-on with automatic redirect URI resolution and signed directory sync webhook (`/api/sync/events`).
5. **90s QR / PIN Device Pairing**: Ephemeral pairing flow (`/api/devices/pair/request`, `/api/devices/pair/approve`, `/api/devices/pair/redeem`) for trusted mobile and browser extensions.
6. **Tamper-Evident Audit Logging**: HMAC-SHA256 hash chained log trail with verification. The chain key is per-install and never a constant — see "Audit chain" below.
7. **Patina Look & Feel**: React + Vite interface with KySecurity Patina theme (`#0d0f14`, cyan `#4deeea`, `Space Grotesk`, `IBM Plex Mono`).

## Audit chain

`internal/audit` writes `DATA_DIR/audit/audit.log` and keeps its key and high-water mark
in `CONFIG_DIR`. The two must be separate volumes: a key stored beside the log it protects
proves nothing.

| Variable | Meaning |
|---|---|
| `CONFIG_DIR` | Holds `audit.key` and `audit.state`. Defaults to `./config`. |
| `AUDIT_KEY` | Optional. Hex, >= 32 bytes (`openssl rand -hex 32`). Unset means the server generates a key into `CONFIG_DIR/audit.key` (0600) on first run. |
| `HMAC_SECRET` | **Legacy verification only.** Entries written before the chain was keyed are chained with this; it is never used to write. Leave it set to whatever the deployment used previously, or unset to fall back to the published constant those entries actually used. |
| `SYNC_SECRET` | Signs the `/api/sync/events` directory webhook. **No default**: unset makes the endpoint reject every request. |

Rules for anyone touching this package:

- **No constant may ever key a written entry.** `legacyDefaultSecret` exists solely to
  verify `v: 0` records and must stay out of the write path.
- **Entries are versioned.** `v: 0` is the legacy public-key format; `v: 1` is keyed and
  includes the version in the hashed payload. `chainHash` is the only hash definition, so
  the write and verify paths cannot drift.
- **The legacy tail is anchored** by a single keyed `audit.rekeyed` marker, written only on
  a genuine first keying (state absent *and* every entry `v: 0`).
- **Do not self-heal.** A missing `audit.state` alongside keyed entries is tampering: the
  logger refuses to recreate it and `VerifyChain` reports it. The high-water mark never
  decreases.
- **Order writes: entry first, state second.** A crash between them under-counts by one,
  which fails open for the newest entry only. The reverse order raises a false truncation
  alarm on every interrupted write, and false alarms are how real alarms get ignored.
- **The audit write is not the caller's to cancel.** `Log` takes a `context.Context` for
  its values, then strips the cancellation with `context.WithoutCancel` and applies its
  own timeout. Handlers pass `r.Context()`, which dies when the client hangs up, and every
  call site discards `Log`'s error — so honouring it would let a client suppress the record
  of what it just did by aborting the connection. Never pass a caller's context straight to
  `auditchain.Append`.
- **A mark write that fails is reported, never rolled back.** The record is already on
  disk, so refusing the append would leave the chain behind the log and fork it on the next
  call. `Log` returns the error; the chain advances anyway.
- **A mark behind the log is caught up; a mark ahead of it is fatal.** On start, every
  record past the mark is verified against the key and against its predecessor, then the
  mark advances to the log's tail — a config volume that was briefly unwritable recovers.
  A log *shorter* than the mark is truncation: `NewLogger` returns `ErrTruncated` and
  `cmd/server` exits, naming both files. This is a boot failure, not a warning.

`python3 scripts/ablate.py` re-runs the ablation suite: it breaks each defence in turn and
fails if any test still passes. Run it after changing `internal/audit` or the sync webhook.

## Verification & Build Commands

- **Backend Unit & Integration Tests**: `go test -v ./...`
- **Frontend Production Build**: `cd frontend && npm run build`
- **Docker Production Image**: `docker build -t kybookmarks-server:latest .`
- **Audit Ablation Suite**: `python3 scripts/ablate.py`

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
- `zero_code_pairing_handoff_spec.md`: contract for pairing this service to KyRecovery with an ephemeral 6-digit PIN, then pushing backups plus a declarative verification recipe. This repo owns the client half (`POST /api/pairing/claim`, `POST /api/backup/push`); KyRecovery owns the spec.
