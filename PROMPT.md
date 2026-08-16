# KyBookmarks

KyBookmarks is a standalone, self-hosted bookmark manager. It provides a web
application, Chrome and Firefox extensions, and Android and iOS applications.
The product is independent from KyPost in v1, but reuses KyPost patterns and
services where useful. Future Ky products may provide a single-pane-of-glass
experience.

The visual design must reuse the existing [`css/`](css/) and [`fonts/`](fonts/)
assets: Space Grotesk for interface text and IBM Plex Mono for technical data.

## Product goals

- Private bookmarks protected by end-to-end encryption.
- Offline-first operation on every client.
- Reliable synchronization across trusted devices and browsers.
- Simple browser migration through standard bookmark HTML import/export.
- Self-hosted deployment using Docker Compose.

## v1 clients

- React, TypeScript, and Vite web application.
- Installable offline-capable web PWA.
- Chrome and Firefox WebExtension extensions using Manifest V3-compatible APIs.
- Flutter Android and iOS applications.
- Browser clients share a TypeScript encryption and synchronization library.
- Flutter implements the same wire format and cryptographic test vectors.

## Authentication and account rules

- KyBookmarks has standalone accounts using email and password.
- Passwords require at least 12 characters. Do not require arbitrary character
  classes; allow long passwords.
- MFA is optional. Supported methods are TOTP and push MFA through the existing
  KyPost push service.
- Users receive one-time MFA recovery codes during setup.
- After three failed login attempts, block login for 15 minutes.
- CAPTCHA and proof-of-work challenges are supported after the threshold.
  Turnstile and PoW settings are configured through `.env`.
- New users are created by an administrator with a temporary password and must
  change it on first login. SMTP is not required.
- Registration is administrator-configurable and invite-only by default.
- Administrators may suspend or delete accounts. Account deletion permanently
  purges active server data after explicit confirmation; administrator-managed
  backups are governed by administrator retention policy.
- Password reset or an administrator reset can restore account authentication,
  but cannot recover bookmark data without the recovery key.
- Losing both the password and recovery key permanently loses access to the
  encrypted vault.
- Production requires HTTPS. HTTP is allowed only for local development.
- Administrators provide their own reverse proxy.

## Encryption and trusted devices

- Every account has one encrypted bookmark vault in v1.
- The vault key is generated on the first trusted client.
- Each bookmark and folder has its own random object key. Object keys are
  wrapped by the vault key.
- Use libsodium-compatible cryptography:
  - Argon2id for password-derived key material.
  - XChaCha20-Poly1305 for authenticated encryption.
- Folder names and all bookmark content and metadata are encrypted. The server
  may see only opaque identifiers, parent/object relationships needed for sync,
  versions, timestamps, tombstones, and synchronization state.
- The server must never receive or log URLs, titles, notes, folder names, or
  favicon contents in plaintext.
- The recovery key is displayed once. The server stores only a verifier and a
  vault-key copy encrypted for recovery.
- QR pairing is the only way to add a trusted device. Pairing follows KyPost:
  single-use code, five-minute expiry, and approval by an existing trusted
  device. There is no password/recovery-key fallback for device enrollment.
- Revoked devices lose synchronization access immediately and delete local
  encrypted data when they next reconnect. An offline device cannot be wiped
  until it reconnects.
- Password changes re-wrap the vault key; they do not re-encrypt every object.
- Encrypted archive exports use a separate archive password.

## Bookmark and folder model

Each bookmark contains:

- URL, restricted to `http` and `https`.
- Title.
- Favicon.
- Optional plain-text description/notes.
- Exactly one parent folder.
- Created and updated timestamps.
- Client-generated version.
- Encrypted position metadata for manual ordering.

Rules:

- Duplicate URLs are allowed.
- Folders may have duplicate sibling names.
- Folder nesting has a hard maximum of five levels, counting top-level folders
  as level one.
- New accounts contain `Bookmarks Bar`, `Other Bookmarks`, and `Mobile
  Bookmarks`.
- A bookmark saved without a selected folder goes to `Other Bookmarks`.
- Tags are deferred to v2.
- v1 stores favicons only. Screenshots and user-uploaded images are deferred.
- Supported favicon formats are PNG, JPEG, WebP, and ICO, with a 256 KB limit.
- Clients may fetch titles and favicons locally; the server does not fetch page
  content.
- Notes and descriptions are plain text, not Markdown.
- Manual order is the saved default. Clients may offer local sorting by name,
  URL, or date without changing saved order.

## Synchronization and conflict handling

- All clients store an encrypted local vault and work offline.
- Synchronization runs automatically when online, on foreground/resume, and
  through a manual `Sync now` action. v1 uses periodic sync; real-time sync
  notifications are deferred to v2.
- Each bookmark and folder has a version.
- Use first-write-wins for concurrent writes.
- A stale or failed write is retained as an opaque failed-write record for
  manual reconciliation, not discarded.
- Retain the latest 20 bookmark versions and all versions required by failed
  reconciliation for 90 days.
- Keep deletion tombstones for 90 days to prevent stale offline resurrection.
- Deleted bookmarks are recoverable from trash for 90 days, then permanently
  deleted.
- Deleting a folder moves it and all descendants to trash while preserving
  hierarchy.
- v1 includes a reconciliation screen with local/server comparison and actions
  to keep local, keep server, or create a new bookmark.
- Users may browse and restore retained bookmark versions.
- Folder changes use versioned conflict handling but do not expose folder
  history.
- The server must use compare-and-swap/version checks and retain failed writes.

## Browser integration

- Chrome and Firefox extensions synchronize the native browser bookmark tree in
  both directions.
- Sync scope is configurable per browser: a dedicated `KyBookmarks` root or
  the entire browser bookmark tree.
- First sync offers merge or replace. Replace removes browser bookmarks only
  after exporting them to recoverable HTML and receiving explicit confirmation.
- Browser deletions become KyBookmarks trash items for 90 days.
- Import, move, and sync operations reject folders exceeding five levels and
  report the affected items.
- Browser bookmark HTML import merges at the top level. Users can fully merge
  imported folders into existing folders. Same-name folder conflicts prompt the
  user to merge or keep separate.
- Standard browser HTML export is plaintext and performed client-side.
- KyBookmarks encrypted archive export/import is also client-side and uses its
  separate archive password.

## Mobile and web behavior

- Android and iOS register as system share targets for saving URLs.
- Mobile apps use a configurable biometric/PIN app lock after inactivity.
- The desktop/web client may offer the same local lock as an optional feature.
- Search is client-side full-text search over URL, title, description, and notes.
  The local encrypted search index is excluded from the server.
- Trash is excluded from normal search, with an explicit `Search trash` option.

## Server and deployment

- Use the KyPost backend approach: Go server, SQLite database, and persistent
  local storage for encrypted blobs.
- Docker Compose is the supported v1 deployment.
- Administrators back up Docker volumes themselves. There is no built-in backup
  and restore feature in v1.
- No per-user storage quotas in v1.
- Public API access is deferred; the API is private to KyBookmarks clients.
- API and synchronization requests have separate per-user rate limits.
- Administrators can view structured audit logs in the web interface. Logs may
  contain authentication, account, administration, and synchronization events,
  but never bookmark content or encrypted metadata. Default retention is 90
  days.

## Security requirements

- Verify ownership and account authorization at the data layer for every
  resource and action.
- Use non-guessable UUID identifiers and server-side version checks.
- Invalidate sessions and device credentials when accounts or devices are
  suspended, deleted, or revoked.
- Protect all state-changing requests with CSRF defenses, SameSite secure
  cookies where applicable, Origin checks, and secure session handling.
- Validate all input server-side, including URL schemes, folder depth, favicon
  type/size, object ownership, versions, and request limits.
- Render all user-controlled text as text. Do not execute bookmark content.
- Apply a strict CSP and security headers, including `X-Content-Type-Options`,
  `frame-ancestors`, and `form-action` restrictions.
- Do not put secrets, vault keys, recovery keys, or server credentials in
  client bundles, logs, URLs, or browser extension messages.
- Opening a bookmark must use a validated `http` or `https` URL and must not
  become an open redirect.

## Deferred to v2

- Sharing bookmarks or folders.
- Tags.
- Screenshots and user-uploaded images.
- Selective folder synchronization.
- Real-time sync notifications.
- Public API and third-party integrations.
- Built-in backup and restore.
- Per-user quotas.
- Additional vaults per account.

