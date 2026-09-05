# Restoring KyBookmarks from a capsule

This is the procedure for bringing a KyBookmarks server back from a `.kycap` backup after the
original is gone. It needs three things, held by three different parties by design:

| Thing | Who has it |
|---|---|
| The capsule (`.kycap`) | KyRecovery, or the local backup directory, or a downloaded copy |
| k custodian cards | The custodians from the suite ceremony (k is usually 2 of 3) |
| A machine to restore on | You |

Nobody can do this alone. KyRecovery cannot open a capsule. One custodian cannot. The server
that made the backup never could. That is the point, and it is also why you should run this
procedure once as a drill before you ever need it.

## What a capsule holds

Everything a fresh KyBookmarks needs to be the old one:

| Path in the capsule | Restores to | What it is |
|---|---|---|
| `kybookmarks.db` | `DATA_DIR/` | Accounts, sessions, devices, the encrypted vault, settings (including the pairing) |
| `config/audit.key` | `CONFIG_DIR/` | Keys the tamper-evident audit chain. Without it the restored log is unverifiable |
| `config/audit.state` | `CONFIG_DIR/` | The chain's high-water mark; the server refuses to start with a log and no mark |
| `config/enum.key` | `CONFIG_DIR/` | Derives the decoy login salt for unknown usernames |
| `config/deployment.key` | `CONFIG_DIR/` | Seals the KyRecovery deposit token stored in the database |
| `config-sso/sso.json` | `DATA_DIR/config/` | KySignOn issuer, client id and client secret, when SSO was configured |
| `recovery.pub` | `DATA_DIR/` | The suite recovery public key, so the restored server comes back pinned |
| `audit/audit.log` | `DATA_DIR/` | The audit chain itself |
| `manifest.json` | reference | Service, version, and these placement notes |

Bookmark content is encrypted in the browser and never readable server-side; no server key
in this list opens it. The restored directory is still the live directory in the clear as
far as the server is concerned: accounts, session tokens, the audit chain and its key.

## Before you start

- **Pick the capsule.** In the KyRecovery dashboard, open Capsules, find the newest one for
  service `KyBookmarks` that is not flagged corrupt, and note its `capsule_id`, `created_at`
  and `digest`. Download it with an operator session. From a local backup directory
  (`KYBOOKMARKS_BACKUP_DIR`), the file is `KyBookmarks.<capsule-id>.kycap`; the newest is the
  one to use unless you have a reason.
- **Gather k custodians.** Each card carries one share, a single line. They type or paste it
  themselves; do not collect the shares in a file, a chat, or an email. Two shares in one
  place is the suite key in one place.
- **Prepare an empty directory** on a machine you trust. The restore refuses a directory that
  is not empty.

## Step 1: open the capsule

With the binary (from a release, or `go build ./cmd/server`):

```bash
kybookmarks-server restore -capsule KyBookmarks.cap-KyBookmarks-XXXXXXXX.kycap -to ./restored
```

With Docker Compose, from the repository directory, mount the capsule and an empty target
directory into a one-off container. Create the target yourself at mode 700 and run the
container as your own user, so the extraction can write into it and what comes out is owned
by you, not by root and not by the image's user. `--no-deps` keeps the real server down:

```bash
mkdir -m 700 restored
docker compose run --rm --no-deps --user "$(id -u):$(id -g)" \
  -v "$PWD/KyBookmarks.cap-KyBookmarks-XXXXXXXX.kycap:/in.kycap:ro" \
  -v "$PWD/restored:/restored" \
  kybookmarks-server restore -capsule /in.kycap -to /restored
```

The command reads the custodian shares from stdin, one per line, then Ctrl-D. Shares are
never accepted on the command line, because argv is world-readable and lands in shell history.

Only for a rehearsal with synthetic test shares, never with real cards, stdin can be a file.
Delete it afterwards; a file holding k shares is the suite key in a file.

On success it prints the authenticated manifest:

```
Restored 8 files from capsule cap-KyBookmarks-1788604943344953387
  service:      KyBookmarks (v0.2.0)
  created:      2026-09-05T10:42:23Z
  recovery key: 51e2d2e1...
  payload hash: 28db3b8d...
```

**Check it against KyRecovery's record.** The capsule ID and `created` must match the deposit
record you noted. The open has already proved the bytes are intact and were sealed to the
suite key; matching the ID and time against the blind store's record is what proves this is
the capsule you meant, not an older one someone substituted.

Failures you may see, and what they mean:

| Message | Meaning |
|---|---|
| `capsule is for service "KyBookmarks", this instance is "X"` | You passed `-service` as something else. Only override it if the backup was made under a different name |
| `shamir: fewer shares than the threshold requires: got 1` | Fewer than k valid lines were read. Check for a missed line or a truncated paste |
| `restore target directory is not empty` | Use an empty directory. The restore never overwrites |
| a decrypt or integrity error | Wrong shares (from a different ceremony), a share mistyped, or a damaged file. Re-download and retry with the custodians |

## Step 2: check what came out

```bash
find restored -type f -printf '%m %p\n'
```

Expect eight or nine files, all mode `600`. `cat restored/manifest.json` shows the version
the backup was made with and where each file goes.

## Step 3: put it in service

Two volumes: `kybookmarks_data` (`/app/data`) and `kybookmarks_config` (`/app/config`). Both
must be empty before the copy, for the same reason Step 1 demands an empty directory. A
capsule carries `kybookmarks.db` but never its `-wal` and `-shm` sidecars; a write-ahead log
left over from the old database would be replayed into the restored one at first open,
mixing two databases. A leftover `audit.state` would describe a log that no longer exists.

```bash
docker compose down
docker compose run --rm --no-deps --entrypoint sh kybookmarks-server -c 'find /app/data /app/config -mindepth 1 | wc -l'
```

That must print `0`. If it does not, the old
volumes still hold data, and you keep a copy before anything else: it holds every change made
after the capsule was sealed, and it is the only record Step 5 can walk. Create the destination
yourself, mode 700; run the copy as root because the image's user cannot write a directory it
does not own:

```bash
mkdir -m 700 old-data
docker compose run --rm --no-deps --user root -v "$PWD/old-data:/out" --entrypoint sh kybookmarks-server \
  -c 'mkdir /out/data /out/config && cp -a /app/data/. /out/data/ && cp -a /app/config/. /out/config/ && find /out -type f | wc -l'
```

The count must equal what the two volumes held, and the command must exit 0. `old-data/` is
now the old live directory in the clear, keys included; it is removed in "Afterwards", not
before Step 5 is done.

Only with the copy confirmed, remove the volumes. This is irreversible:

```bash
docker compose down -v
docker compose run --rm --no-deps --entrypoint sh kybookmarks-server -c 'find /app/data /app/config -mindepth 1 | wc -l'
```

With `0` confirmed, copy the restored files in and start:

```bash
docker compose run --rm --no-deps --user root --entrypoint sh \
  -v "$PWD/restored:/from:ro" kybookmarks-server -c '
    cp -a /from/kybookmarks.db /from/recovery.pub /app/data/ 2>/dev/null;
    mkdir -p /app/data/audit /app/data/config &&
    cp -a /from/audit/audit.log /app/data/audit/ &&
    [ -f /from/config-sso/sso.json ] && cp -a /from/config-sso/sso.json /app/data/config/;
    cp -a /from/config/. /app/config/ &&
    chown -R kybookmark:kybookmark /app/data /app/config &&
    find /app/data /app/config -type f -exec chmod 600 {} +'
docker compose up -d
```

Keep `SYNC_SECRET`, `AUDIT_KEY` (if it was supplied by environment rather than the file) and
the KySignOn configuration identical to the old deployment. If `AUDIT_KEY` was in the
environment, the environment wins over `config/audit.key`; either remove the variable so the
restored file is read, or supply the same value. Never print a key to a terminal or type one
on a command line.

**Bare binary.** Point `DATA_DIR` at the restored data files and `CONFIG_DIR` at
`restored/config`, laid out as the table above says, and start.

## Step 4: prove it

1. Open the server and sign in with an existing account and its master password. Bookmarks
   decrypting proves the vault rows came across intact.
2. Open Admin Panel, Backup & Recovery. If the backup was paired, the recovery key shows as
   pinned with the same key ID as before, and the pairing shows as paired: the token is in the
   database, sealed under the restored `deployment.key`. Click Back up now to prove it. If the
   screen says the key is missing, `recovery.pub` did not come across; re-pair, which is
   refused unless KyRecovery hands back the same key.
3. Open Audit Trail and run Verify. The chain must verify: the last events before the
   restore are there, followed by your sign-in.
4. If SSO was configured, sign in once through KySignOn.

## Step 5: decide what to trust

The restore proves the service works. It does not make the restored state current or safe.
Everything comes back as of the capsule's `created_at`: accounts, passwords, paired devices,
sessions, the pairing. Anything you revoked or changed after that moment is undone, and a
session cookie minted before the capsule still validates against the restored server.

1. **Revoke every session.** There is no per-user control in the UI; all sessions live in
   one table, and CSRF tokens live with them, so one statement invalidates everything at
   once. Stop the server first, so the write-ahead log is quiet:

   ```bash
   docker compose down
   docker compose run --rm --no-deps --user root --entrypoint sh kybookmarks-server \
     -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /app/data/kybookmarks.db "DELETE FROM sessions; DELETE FROM pairing_sessions;"'
   docker compose up -d
   ```

2. Walk the old audit log in `old-data/data/audit/audit.log` from `created_at` to the moment
   the old server was lost, and re-apply what happened after the capsule: suspended or
   deleted accounts, revoked devices, SSO links removed.
3. If the reason for the restore was a suspected compromise rather than hardware loss, treat
   the restored keys as exposed and rotate what can be rotated. A restore from before a
   compromise brings the attacker's access back with the service unless you do this.

   **Never rotate `audit.key` by hand.** The whole chain is keyed to it; a new key forks the
   chain and every entry before the fork becomes unverifiable. It has no secret value beyond
   the log it protects, so an exposed audit key means an attacker could forge history, not
   read anything; the answer is to preserve `old-data/` as the untouched record.

   Rotate, in this order:

   - `enum.key`: stop the server, delete `CONFIG_DIR/enum.key`, start. A new one is minted;
     only the decoy salt for unknown usernames changes.
   - `deployment.key`: it seals only the KyRecovery deposit token. Unpair in the Backup tab,
     stop the server, delete `CONFIG_DIR/deployment.key`, start, re-pair. The key pin stays,
     so re-pairing is accepted only to the same suite key. Ask the KyRecovery admin to revoke
     the old token there.
   - `SYNC_SECRET`: re-issue it from KySignOn's paired-system page and update the compose
     environment.
   - KySignOn client secret: rotate it in KySignOn and save the new value in the SSO tab.

   ```bash
   docker compose down
   docker compose run --rm --no-deps --user root --entrypoint sh kybookmarks-server \
     -c 'rm /app/config/enum.key /app/config/deployment.key && ls -A /app/config'
   docker compose up -d
   ```

   The listing must still show `audit.key` and `audit.state`. Then re-pair from the Backup
   tab and click Back up now, so the recovered server has a capsule that reflects the rotation.

## Afterwards

- Delete the `restored/` directory once the server runs from its own copy, and `old-data/`
  once Step 5 is done. Both are the live directory in the clear. Files in `old-data/` are
  root-owned after the copy, so `sudo rm -rf old-data`.
- The custodians' cards are unchanged; a restore does not consume them. If a card was
  exposed during the restore (read aloud, photographed, pasted anywhere shared), that is a
  key compromise for the whole suite, not for one server: run a new ceremony.
- Make a backup from the restored server so the newest capsule reflects the recovery.

## Drill it

Run Steps 1 and 2 against the latest capsule on a scratch machine once a quarter, with the
real custodians and their real cards, and then delete the output. The in-app drill proves the
capsule format restores; only this proves the cards do.
