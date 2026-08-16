# KyBookmarks Design

This document turns [`PROMPT.md`](PROMPT.md) into a small implementation plan.
The spelling of this filename is retained as requested.

## 1. Architecture

```text
                         +----------------------+
                         | Go + SQLite server   |
                         | auth, sync, admin    |
                         +----------+-----------+
                                    |
                         opaque encrypted records
                                    |
      +-----------------+-----------+------------+-----------------+
      |                 |                        |                 |
 React/Vite PWA   Chrome extension       Firefox extension   Flutter apps
      |                 |                        |          Android / iOS
      +-----------------+------------------------+-----------------+
              local encrypted vault + client-side search
```

The server is a synchronization service, not a content service. Clients own
decryption, rendering, title/favicon fetching, search indexing, export, and
import. The server owns authentication, device authorization, opaque record
storage, version checks, tombstones, rate limits, and administrative audit
logs.

Reuse KyPost patterns for Go/SQLite, React/Vite, TOTP, proof-of-work, Turnstile,
admin screens, and QR pairing. Keep the KyBookmarks account and database
standalone; the KyPost push service is the only approved v1 service integration.

## 2. Repository layout

```text
backend/                 Go HTTP server and SQLite store
frontend/                React/Vite web app and PWA
packages/crypto/         TypeScript crypto primitives and object envelopes
packages/sync/           TypeScript versions, deltas, tombstones, conflicts
extensions/              Shared WebExtension code and browser adapters
mobile/                  Flutter Android/iOS application
deploy/                  Docker Compose, env example, and volume docs
docs/                    Protocol, threat model, and operator documentation
```

Start with the smallest working vertical slice: account login, first-device
vault creation, one encrypted bookmark, sync, and local search. Add the other
clients after the protocol is covered by fixtures.

## 3. Encryption model

### Keys

```text
password --Argon2id--> password key --wraps--> vault key
recovery key ---------> recovery key --wraps--> vault key
vault key -------------> wraps per-object keys
object key -------------> encrypts one folder/bookmark payload
```

- Generate keys with a cryptographically secure random source on a trusted
  client.
- Use XChaCha20-Poly1305 with unique nonces and authenticated associated data.
- Associated data should bind the object ID, object type, account ID, version,
  and protocol version to prevent record substitution and replay.
- The server stores encrypted key wrappers and ciphertext, never plaintext
  content or vault keys.
- Password changes only replace the password wrapper around the vault key.
- A new device receives the vault key through the approved QR pairing flow;
  it does not receive a password-derived secret from the server.
- The recovery key is shown once. Store a verifier for validation and a vault
  key wrapper encrypted under a recovery-key-derived key.

`ponytail:` Keep one vault key and per-object wrappers in v1. A more elaborate
key hierarchy is only needed when v2 sharing requires folder-level delegation.

### Object envelope

The encrypted payload should contain the complete logical object, including
names, URLs, notes, favicon bytes, timestamps, parent folder ID, and position.
The synchronization envelope contains only what the server needs:

```json
{
  "object_id": "uuid",
  "object_type": "bookmark|folder",
  "version": 12,
  "parent_id": "uuid-or-null",
  "updated_at": "server-timestamp",
  "deleted": false,
  "ciphertext": "base64url",
  "nonce": "base64url",
  "key_wrapper": "base64url",
  "protocol_version": 1
}
```

`parent_id`, version, timestamps, and deletion state are synchronization
metadata, not user content. Use UUIDs and account-scoped ownership checks.

## 4. Server data model

Use SQLite for indexes and a persistent local blob directory for ciphertext.
Keep the schema deliberately small:

- `accounts`: email, password verifier, status, MFA settings, timestamps.
- `sessions`: hashed session/token identifiers, expiry, revocation state.
- `devices`: device UUID, account ID, public pairing material, status,
  last-seen timestamp, and revocation timestamp.
- `vaults`: account ID, protocol version, encrypted password/recovery wrappers.
- `objects`: account ID, object UUID/type, parent UUID, current version, blob
  path, timestamps, and deletion state.
- `object_versions`: retained version pointers and opaque failed-write blobs.
- `tombstones`: object UUID, version, deletion time, and expiry.
- `mfa_recovery_codes`: hashed one-time codes and consumed timestamps.
- `audit_events`: event type, actor, result, coarse request data, and timestamp.
- `pairing_sessions`: hashed one-time QR pairing secret and five-minute expiry.

Store encrypted payloads under a non-guessable path such as:

```text
data/blobs/<account-uuid>/<object-uuid>/<version>.blob
```

Never use user-provided names as paths. Write blobs atomically, then commit the
SQLite pointer. On failure, leave the opaque failed write available for
reconciliation.

## 5. Synchronization protocol

1. Client authenticates and presents a trusted-device credential.
2. Client sends its per-account sync cursor and local object versions.
3. Server returns opaque changes, tombstones, and failed writes owned by that
   account.
4. Client decrypts and applies changes locally.
5. Client uploads new encrypted envelopes with expected current versions.
6. Server accepts only the first valid write for a version transition.
7. A stale write receives a conflict response and is retained as a failed
   write; it is never silently overwritten or dropped.

Use a compare-and-swap transaction for every object write. The transaction must
verify account ownership, expected version, object type, parent existence, and
folder depth before changing the current pointer.

`ponytail:` Use periodic sync plus foreground/resume sync in v1. Add push or
WebSocket invalidation only after measurements show polling is insufficient.

### Conflict UI

The client must show decrypted local and server versions side by side. Actions:

- Keep local: create a new valid version from local data.
- Keep server: discard the local failed write after confirmation.
- Create new bookmark: preserve both records, including duplicate URLs.

Retain the latest 20 bookmark versions and reconciliation-required versions for
90 days. Keep tombstones for 90 days so offline clients cannot resurrect data.

## 6. Folder and bookmark rules

- Use explicit object IDs; names are never identities.
- A bookmark has exactly one parent folder.
- Duplicate URLs and sibling folder names are valid.
- Count top-level folders as level 1; reject level 6 and deeper.
- Deleting a folder recursively tombstones the folder and descendants while
  retaining their parent links for restoration.
- New accounts seed `Bookmarks Bar`, `Other Bookmarks`, and `Mobile Bookmarks`.
- Default bookmark destination is `Other Bookmarks`.
- URL validation accepts only `http` and `https`; reject dangerous schemes before
  storage and again before opening.
- Favicons are client-fetched and limited to PNG, JPEG, WebP, or ICO and 256 KB.
- Render title, notes, and folder names as plain text. Do not use Markdown or
  HTML rendering.

## 7. Browser synchronization

The extension has two explicit modes:

1. Dedicated root: sync only below a `KyBookmarks` browser folder.
2. Entire tree: map the browser bookmark tree to the KyBookmarks tree.

On first sync, offer:

- Merge into KyBookmarks.
- Replace browser bookmarks with KyBookmarks.

Before replacement, export the current browser tree to HTML, save it locally,
and require explicit confirmation. Browser deletion becomes a KyBookmarks
tombstone, not an immediate permanent delete. Native browser nodes map to
KyBookmarks object IDs through extension-local state and encrypted sync data.

Use browser APIs for bookmark events and a shared TypeScript sync package for
version and conflict behavior. Keep browser-specific API differences in small
adapters.

## 8. Client storage and search

- Store the local vault in IndexedDB on web/extensions and the platform-secure
  encrypted store available to Flutter.
- Keep vault keys out of ordinary local storage; use Web Crypto/extension secure
  storage and OS-protected storage where available.
- Lock the local client after configurable inactivity. Mobile supports biometric
  or PIN unlock; desktop/web may offer it optionally.
- Build the full-text index locally from decrypted URL, title, description, and
  notes. Never upload the index.
- Exclude trash from normal search; add an explicit trash-search mode.
- The PWA must queue writes offline and show sync state and failed writes.

## 9. Authentication and request security

Reuse KyPost’s proven auth and challenge patterns, but keep sessions and account
data in KyBookmarks. Required controls:

- Argon2id password verification with a high enough memory/time cost.
- Secure, HttpOnly, SameSite cookies for web sessions; short-lived device
  credentials with rotation and revocation.
- CSRF tokens and Origin validation on all state-changing browser requests.
- Per-account and per-IP rate limits for login, sync, pairing, and archive APIs.
- Three failed logins trigger a 15-minute block; Turnstile and PoW are configured
  through `.env` and validated server-side.
- MFA is optional; TOTP secrets and push credentials are protected server-side.
- MFA recovery codes are stored hashed and are single-use.
- Account/device suspension and deletion revoke sessions and device credentials.
- Every resource lookup verifies account ownership in the data layer.
- Admin routes require server-side role checks and must not expose bookmark data.
- Do not log request bodies, URLs, folder names, notes, titles, or favicon data.
- Return generic authentication errors to avoid account enumeration.

Set security headers on the web app, including a strict CSP, `X-Content-Type-
Options: nosniff`, `Referrer-Policy: no-referrer`, and `frame-ancestors 'none'`.

## 10. Imports and exports

All imports and exports run on a trusted client:

- Browser HTML import merges at the top level.
- Same-name folder conflicts prompt the user to merge or keep separate.
- Over-depth folders are rejected with item-level errors.
- Plain HTML export is compatible with browsers and is intentionally plaintext.
- Encrypted KyBookmarks archive export uses a separate archive password.
- Import must validate archive structure, protocol version, object IDs, limits,
  authentication tags, and folder depth before applying changes.

## 11. Deployment and operations

Docker Compose must provide:

- The Go server.
- Persistent SQLite storage.
- Persistent encrypted blob storage.
- A documented `.env.example` for auth, CAPTCHA, PoW, push MFA, paths, and
  rate limits.

Administrators bring their own reverse proxy and manage HTTPS. Administrators
also back up the Docker volumes. There is no built-in backup/restore or storage
quota system in v1.

Expose only health and readiness information that contains no account or
bookmark data. Audit logs are visible to administrators, retain 90 days by
default, and include only authentication, account, admin, and synchronization
events.

## 12. Delivery order

1. Protocol fixtures and crypto test vectors.
2. Go/SQLite auth, devices, vault envelopes, object storage, CAS writes, and
   tombstones.
3. React/Vite PWA with first-device setup, QR pairing, local vault, CRUD,
   search, trash, history, reconciliation, and import/export.
4. Shared browser extension with Chrome/Firefox adapters and two-way bookmark
   sync.
5. Flutter Android/iOS clients, share targets, local lock, and offline sync.
6. Docker Compose, operator documentation, audit UI, and security testing.

Every non-trivial parser, cryptographic boundary, version transition, folder
depth check, import/export path, and authorization path requires at least one
runnable test. Prefer table-driven unit tests and protocol fixtures over
end-to-end test scaffolding until the vertical slice works.

## 13. Explicit v2 backlog

- Bookmark and folder sharing.
- Tags.
- Screenshots and user-uploaded images.
- Selective folder sync.
- Real-time sync notifications.
- Public API and third-party integrations.
- Built-in backup and restore.
- Per-user quotas.
- Multiple vaults per account.

