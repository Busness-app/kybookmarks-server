# KyBookmarks Server

Zero-knowledge bookmark sync for the KySecurity suite. Bookmarks are encrypted in the browser;
the server stores opaque payloads, syncs them between trusted devices, signs users in through
KySignOn, and keeps a tamper-evident audit chain. `AGENTS.md` is the engineering contract;
this file is for the operator.

## Run it

```bash
docker compose up -d
```

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

**A KyRecovery on your own network.** Two things are needed, and a value in `.env` alone does
neither:

```bash
KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY=true \
KYBOOKMARKS_DNS=192.168.1.1 \
docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d --force-recreate
docker inspect KyBookmarks-Server --format '{{.HostConfig.Dns}}'   # must print [192.168.1.1]
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
