# KyBookmarks Server

Zero-knowledge bookmark sync for the KySecurity suite. Bookmarks are encrypted in the browser;
the server stores opaque payloads, syncs them between trusted devices, signs users in through
KySignOn, and keeps a tamper-evident audit chain. `AGENTS.md` is the engineering contract;
this file is for the operator.

## Run it

Published image:

```bash
docker compose up -d
```

Source install (never paste this into a published-image install: the build overlay wins over a
`KYBOOKMARKS_IMAGE` digest pin, and a source install must set this line before its first `up -d` on a
new checkout; an install from before the published image existed has no such line yet, so run
this block once and confirm with `docker compose config --images`, which must print
`kybookmarks-server:local` rather than the `ghcr.io` name):

```bash
(umask 077; t=$(mktemp ./.env.XXXXXX) && touch .env \
  && cf=$({ grep '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } | tail -n1 | cut -d= -f2-) && cf=${cf:-docker-compose.yml} \
  && case ":$cf:" in *:docker-compose.build.yml:*) ;; *) cf="$cf:docker-compose.build.yml";; esac \
  && { grep -v -e '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } > "$t" \
  && printf 'COMPOSE_FILE=%s\n' "$cf" >> "$t" && mv "$t" .env)
docker compose up -d
```

Update a published-image install on the rolling tag:

```bash
docker compose pull && docker compose up -d
```

A digest-pinned install (`KYBOOKMARKS_IMAGE` in `.env`) gets nothing from `pull`: re-run the pin recipe in
`docker-compose.yml` with the commit sha you want first, or delete that line to follow `:latest` again.

Open `http://127.0.0.1:5869` and complete first-run setup. Every variable below has a default
except `SYNC_SECRET`, which has none on purpose.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `5869` | Listen port |
| `DATA_DIR` | `./data` (`/app/data` in the image) | Database, audit log, `recovery.pub`, `config/sso.json` |
| `CONFIG_DIR` | `./config` (`/app/config`) | `audit.key`, `audit.state`, `enum.key`, `deployment.key`. Keep it on a separate volume from `DATA_DIR` |
| `AUDIT_KEY` | unset | Optional. Exactly 32 bytes, hex or base64. Unset mints `CONFIG_DIR/audit.key` on first run |
| `HMAC_SECRET` | unset | Legacy: verifies audit entries written before the chain was keyed. Never used to write |
| `SYNC_SECRET` | unset | KySignOn directory-sync signing secret, at least 16 bytes. Unset disables the webhook |
| `KYBOOKMARKS_BACKUP_DIR` | unset | Directory for sealed local backup copies. Unset means none; `/app/backups` is a volume in the compose file |
| `KYBOOKMARKS_BACKUP_KEEP` | `7` | How many local copies to keep; older ones are pruned. Must be at least 1 |
| `KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL` | `24h` | Default schedule only. The admin sets the live one in the Backup tab; `0` is off, the floor is `15m` |
| `KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY` | `false` | Admit a KyRecovery on a private or CGNAT address. HTTPS stays mandatory; loopback never |
| `KYBOOKMARKS_DNS` | unset | Only in `docker-compose.lan-dns.yml`: the container's DNS server, for LAN-only names |

SSO is configured by an admin in the app, not by environment. When registering KyBookmarks as
a client in KySignOn, set its back-channel logout URI to
`https://<host>/api/auth/oidc/backchannel-logout` so a KySignOn sign-out or offboarding ends
KyBookmarks sessions too. Without it, an SSO session lasts until it expires or the user signs
out here.

## Disaster recovery

Every backup is a `.kycap` capsule sealed to the suite recovery public key. The server holds
nothing that opens one; only k of n custodian cards from the suite ceremony do. That is why a
capsule can sit in a blind store or a shared directory.

**What a capsule carries:** the database, the four keys in `CONFIG_DIR`, the SSO settings if
configured, the pinned recovery key, and the audit log. Bookmark content stays encrypted under
each user's key; no server key opens it.

**Where capsules go.** One run seals once and delivers everywhere that is configured:

- **KyRecovery**, paired from the Backup tab with a six-digit code the KyRecovery admin
  generates. Pairing pins the suite key and stores a deposit credential, sealed at rest under
  `deployment.key`.
- **A local directory**, `KYBOOKMARKS_BACKUP_DIR`, for an instance with no KyRecovery. Pin the
  suite public key by hand in the Backup tab; the ceremony page shows it with the k-of-n it
  was split with.

A pinned key with nowhere to send a capsule is a precondition failure the screen explains, not
a silent no-op.

**Why TLS matters even though the capsule is sealed.** The pairing hands this server the
public key it will seal every future backup to, trust on first use; the deposit token and the
receipts travel on the same connection. HTTPS protects those three, not the capsule. Before
trusting a pairing, compare the key ID the Backup tab shows with the ceremony card, or pin
the key by hand and let the pairing be refused if KyRecovery presents a different one.

**A KyRecovery on your own network.** Everything goes in `.env`, and the container must be
recreated to pick it up:

The snippet appends `docker-compose.lan-dns.yml` to whatever `COMPOSE_FILE` chain `.env` already
holds (build overlay, local override) and leaves the rest of the chain alone; the resolver and the private-recovery flag
sit next to it: the resolver comes from an exported
`KYBOOKMARKS_DNS` (`export KYBOOKMARKS_DNS=<addr>`; fish: `set -x KYBOOKMARKS_DNS <addr>`) or, when that is unset, from the `KYBOOKMARKS_DNS` line
already in `.env`; there is no default, the block refuses to guess. An exported value overrides
`.env`, so re-running is a no-op only while `KYBOOKMARKS_DNS` is unset in your shell; the flag is set to true. One block for every install type:

```bash
(umask 077; touch .env \
  && cf=$({ grep '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } | tail -n1 | cut -d= -f2-) && cf=${cf:-docker-compose.yml} \
  && dns=${KYBOOKMARKS_DNS:-$({ grep '^KYBOOKMARKS_DNS=' .env || [ $? -eq 1 ]; } | tail -n1 | cut -d= -f2-)} \
  && : "${dns:?no resolver chosen: export KYBOOKMARKS_DNS=<your LAN resolver> (fish: set -x KYBOOKMARKS_DNS <addr>), then re-run this block}" \
  && case ":$cf:" in *:docker-compose.lan-dns.yml:*) ;; *) cf="$cf:docker-compose.lan-dns.yml";; esac \
  && t=$(mktemp ./.env.XXXXXX) && { grep -v -e '^COMPOSE_FILE=' -e '^KYBOOKMARKS_DNS=' -e '^KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY=' .env || [ $? -eq 1 ]; } > "$t" \
  && printf 'COMPOSE_FILE=%s\nKYBOOKMARKS_DNS=%s\nKYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY=true\n' "$cf" "$dns" >> "$t" && mv "$t" .env)
docker compose up -d --force-recreate
docker inspect KyBookmarks-Server --format '{{.HostConfig.Dns}}'   # must print the resolver you chose
```

Turning it off: remove the resolver and the flag, strip only `docker-compose.lan-dns.yml` from
`COMPOSE_FILE` (a build overlay or local override in the chain survives), and recreate:

```bash
(umask 077; t=$(mktemp ./.env.XXXXXX) && touch .env \
  && cf=$({ grep '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } | tail -n1 | cut -d= -f2- | tr ':' '\n' | grep -vx docker-compose.lan-dns.yml | paste -sd: -) \
  && { grep -v -e '^COMPOSE_FILE=' -e '^KYBOOKMARKS_DNS=' -e '^KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY=' .env || [ $? -eq 1 ]; } > "$t" \
  && { [ -z "$cf" ] || [ "$cf" = docker-compose.yml ] || printf 'COMPOSE_FILE=%s\n' "$cf" >> "$t"; } && mv "$t" .env)
docker compose up -d --force-recreate
```

**Schedule.** Off, or 15 minutes to a year, set in the Backup tab. The loop polls the setting
every minute, so a change needs no restart, and the next run counts from the last attempt,
successful or not.

**Unpairing** removes the URL and the sealed token from this server and nothing else: the key
pin, the receipts and the local copies stay, so a later pairing is accepted only to the same
key. The credential dies when the KyRecovery admin revokes it there.

**Restoring** is the product's job, not KyRecovery's: `docs/RESTORE.md` is the runbook, from
opening the capsule with the custodians through deciding what to trust afterwards. Run it as a
drill before you need it. The Backup tab's restore drill proves the format; only the runbook
with real cards proves the cards.

Drills validate the opened capsule's recipe, core files, database integrity, required tables,
and active administrator using read-only SQLite access. HTTP and CLI drills against the same
data directory are serialized; a competing run is refused until the first finishes. Scratch
files stay under `DATA_DIR/drill` (0700) and are removed on return; the `.lock` file remains.

**Command line.** `kybookmarks-server backup-drill`, `export-capsule <out>`, `deposit`, and
`restore -capsule <file> -to <dir>` (shares on stdin). `serve` is the default.
