# KyBookmark Server

KyBookmark Server is the zero-knowledge encrypted bookmark synchronization and management server for the KySecurity Suite of software (KySignOn, KyPost, KyPasswords, KyBookmarks, KyNotes).

## Core Capabilities & Responsibilities

1. **Zero-Knowledge End-to-End Encryption**: Bookmarks, notes, titles, and custom folder names are encrypted on trusted clients using Web Crypto (AES-256-GCM / PBKDF2). The server stores only opaque encrypted payloads, UUIDs, versions, parent relationships (max 5 depth), and 90-day tombstones.
2. **Deterministic Versioning & CAS Synchronization**: First-write-wins compare-and-swap concurrency. Failed concurrent writes are preserved for 90-day reconciliation rather than silently dropped.
3. **Netscape Bookmark HTML Import & Export**: Standard browser bookmark file parsing and export supporting top-level merging and folder trees up to 5 levels.
4. **KySignOn SSO & Account Replication**: Native OIDC PKCE single sign-on with automatic redirect URI resolution and signed directory sync webhook (`/api/sync/events`).
5. **90s QR / PIN Device Pairing**: Ephemeral pairing flow (`/api/devices/pair/request`, `/api/devices/pair/approve`, `/api/devices/pair/redeem`) for trusted mobile and browser extensions.
6. **Tamper-Evident Audit Logging**: SHA-256 HMAC hash chained log trail with verification.
7. **Patina Look & Feel**: React + Vite interface with KySecurity Patina theme (`#0d0f14`, cyan `#4deeea`, `Space Grotesk`, `IBM Plex Mono`).

## Verification & Build Commands

- **Backend Unit & Integration Tests**: `go test -v ./...`
- **Frontend Production Build**: `cd frontend && npm run build`
- **Docker Production Image**: `docker build -t kybookmarks-server:latest .`

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
