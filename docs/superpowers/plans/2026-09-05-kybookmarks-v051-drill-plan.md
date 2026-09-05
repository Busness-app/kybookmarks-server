**Repo:** kybookmarks-server
**PR:** #18 — https://github.com/Busness-app/kybookmarks-server/pull/18 (merged auth baseline)
**PR:** #19 — https://github.com/Busness-app/kybookmarks-server/pull/19 (merged backup baseline; no new PR)
**Worktree:** /home/yoshi/busness.app/kybookmarks-server (master; planning from fetched origin/master 95852bb1db6f3ae54ad6008799c3a2968f180e28)

# Post 291: v0.5.1 drill migration and recovery proof

Owner: `Usagi / GPT-6 / basalt`; myslop folder `kybookmarks-kyrecovery-deposit`, claimed in post 299. Requested scope for this session: claim and plan. Implementation, tests and deployment have not been performed. Keep the claim for execution; do not interpret this document as code-complete or live-proof-complete.

## Verified starting point

- Fetched origin/master on 2026-09-05: `95852bb1db6f3ae54ad6008799c3a2968f180e28`. Local master remains `fb571d5`; existing untracked `docs/` and locked `.claude/worktrees/deposit` remain untouched.
- `go.mod` pins ky-primitives v0.5.0, Go 1.26.6. Shared auth, syncauth, oidcverify, recoveryclient, backup UI/CLI and restore documentation are already merged.
- `internal/backup/drill.go` captures the pre-seal payload. Callers are the HTTP drill handler, `cmd/server/backup.go`, and drill tests. v0.5.1's installed source requires `func(dir string, opened capsule.Manifest) []recoveryclient.Check`.
- Current checks test payload-member presence, SQLite integrity, `accounts`, `vault_objects`, `settings`, and an active admin. The collector's recipe contains `required_tables` and `require_any_admin`; checks currently ignore that recipe.
- The library opens each drill in its own 0700 directory, removes it on return, and sweeps directories older than one hour. Neither product drill entry point currently serializes calls against the same data directory.
- `NewSealer` uses `kybookmarks:setting:kyrecovery_token`. Existing `TestSealerRoundTrip` is a same-version round trip, not an upgrade compatibility proof. Installed v0.5.0/v0.5.1 sealer source is identical, which supports but does not replace that proof.
- Root AGENTS.md on remote main owns backup contracts; there are no child AGENTS.md files on that revision. Read it and `/home/yoshi/busness.app/AGENTS.md` again before implementation. The parent's per-product adoption paragraph is stale; its invariants remain applicable.

## 1. Prepare an isolated implementation branch

Re-read the board and preserve any newer claim or steering. Fetch again and compare the remote head with the baseline above. Use a new worktree such as `.claude/worktrees/drill-v051` on `fix/recovery-drill-v051` from origin/master; do not reuse or unlock the deposit worktree. If that path or branch exists, inspect it before using it. Copy this plan into the new worktree without overwriting other plans.

Before upgrading, generate a small synthetic pairing fixture using the pinned v0.5.0 implementation: fixed test deployment key, sealed dummy token, settings rows and a synthetic pinned public key/topology. Record fixture provenance and the producing version. No live keys or credentials belong in fixtures.

## 2. Migrate the shared product check function

Expected changes: `go.mod`, `go.sum`, `internal/backup/drill.go`, its tests, the HTTP and CLI callers. Change `payload.go` only if a shared declaration is needed to keep collector and validator requirements aligned.

1. Pin `github.com/Busness-app/ky-primitives@v0.5.1` and tidy. Keep the existing Go requirement and review unrelated module changes.
2. Make `Checks(dir string, opened capsule.Manifest)` the callback directly; remove the captured-payload closure. Both production callers pass the same function. Do not cast or substitute an unverified manifest.
3. Validate the opened service name and the recipe object at the boundary. Decode `required_tables` as the JSON-produced `[]any`, checking every item is a nonempty string. Require a correctly typed `require_any_admin: true`. Missing, malformed, or weakened required fields produce failed checks rather than skipping verification.
4. Use the authenticated `opened.Files` for member checks. Require the fixed core members even when the manifest omits them: `kybookmarks.db`, `config/{audit.key,audit.state,enum.key,deployment.key}`, `audit/audit.log`, and `manifest.json`. SSO config and `recovery.pub` remain conditional as in the collector; every listed member must exist as a regular file.
5. Validate paths before filesystem access: nonempty, clean relative capsule paths, no absolute paths, traversal, ambiguous separators or NULs. Use confined filesystem access where needed so a symlink cannot turn a check into an outside read. Do not add new recipe path fields merely for this migration.
6. Preserve mandatory tables `accounts`, `vault_objects`, `settings` and the active-admin predicate independently of recipe content. A valid recipe can add table checks but cannot remove these. Bind table names as SQL parameters. Malformed recipes remain failures even if the database otherwise passes.
7. Keep verification read-only using an explicit SQLite file URI with `mode=ro` and properly encoded paths. Never call `store.NewStore` in validation: it creates schema and can hide a missing table. Missing databases must stay missing after a failed check.

## 3. Serialize drill entry points without copying the library

Add one small product `RunDrill` wrapper used by HTTP and CLI. It owns collection, the protected scratch root, invocation of library Drill, and the common Checks callback. Keep seal/open/extract/cleanup inside recoveryclient.

Serialize against the canonical data directory across HTTP and CLI processes. A handler mutex alone does not cover CLI. For the existing Linux target, use an OS advisory lock on a persistent owner-only file under the drill root, with the already present `golang.org/x/sys/unix`; do not unlink a held lock file. Refuse a competing run with an explicit busy result (HTTP 409; CLI failure), and release on every return/process exit. Check supported build targets before choosing build constraints; unsupported platforms must not silently run unlocked. Acquire before collection and the library's stale-directory sweep. This is a real shared-root invariant, not a reason for a new lock service or framework.

Confirm the root is owner-only even if it already exists. Add focused concurrency evidence: two subprocesses using one root cannot both enter; a failed run releases its lock; different roots remain independent. Assert the normal library drill removes its temporary cleartext files.

## 4. Add failure and upgrade regression proofs

Reuse existing seed/fixture helpers and table-driven tests. Negative cases must assert the relevant failed check, not merely that some unrelated prerequisite failed.

| Case | Required result |
|---|---|
| Real Collect → seal → open → Checks | Passes with JSON-decoded recipe lists; no captured payload needed |
| Listed file missing; mandatory file omitted from manifest | Fails member validation in both cases |
| Nil/non-object recipe, wrong list type, mixed list elements, false/wrong-type admin flag | Fails explicitly, never silently skips |
| Empty/absolute/traversing/unclean path; symlink escape | Fails before accessing anything outside scratch |
| Required application table dropped | Fails even if recipe omits that table; validator does not recreate it |
| No active admin, including only suspended admins | Fails despite a valid database and all members |
| Missing SQLite file | Fails without creating a database or schema |
| v0.5.0 synthetic sealed pairing loaded under v0.5.1 | Same URL/token/key ID/topology load using unchanged settings keys and label |
| Wrong deployment key or label | Existing ciphertext cannot be opened |

Drive at least one positive and malformed-recipe case through the real library drill, so JSON decoding and callback wiring are exercised. Direct callback cases cover paths or damaged extracted files that the library normally rejects earlier.

Extend existing product API tests only for uncovered acceptance criteria: a deposit using the old pairing fixture, successful receipt handling, and unpair preserving receipts/local copies as well as the pin. Reuse existing tests for admin/CSRF enforcement, POST-only export, export audit failure, key conflict, local 0600 copies, schedule limits and token-free status. Run existing syncauth/OIDC tests; do not replace those integrations.

Prove `TestNothingInTheServerDecrypts` catches a temporary forbidden `capsule.Open` call in production code, then remove the probe and rerun. Only `cmd/server/backup.go:restore` remains exempt. Never widen the exemption to make the drill wrapper pass.

## 5. Repository gates and documentation

Run focused backup/API/CLI tests while editing, then the full gates once the change stabilizes:

```bash
go build ./...
go vet ./...
go test -race ./...
python3 scripts/ablate.py
```

In `frontend/`, run `npm ci` and `npm run build`. Build the existing Dockerfile for the synthetic/live proof. Check all GitHub CI jobs on the exact pushed SHA; the scheduled ky-primitives default-branch compatibility workflow is an early warning, not a PR merge gate.

Update root AGENTS.md with the opened-manifest validation and drill serialization contracts after they exist. Check README and `docs/RESTORE.md` for changed commands, result claims, version references and file-placement assumptions. Keep the runbook's synthetic proof distinct from real custodian-card recovery. This planning-only change introduces no runtime or ownership contract; the existing AGENTS.md files are intentionally unchanged now.

Suggested commits: (1) v0.5.1 callback/validation plus regression and compatibility tests; (2) shared drill serialization plus its tests and final documentation. Open one focused PR and drive repository CI and the autonomous reviewer to clearance on its current head. Report the tested SHA for human merge.

## 6. Disposable product proof

Use a fresh synthetic instance with isolated DATA_DIR, CONFIG_DIR and local backup directory. Create an admin through setup so `audit.state` exists. Generate a synthetic 2-of-3 recovery key; keep all test secrets out of logs and the board.

1. Pin by hand, back up locally, inspect mode 0600 and audit results, and run a passing drill. Confirm scratch cleanup.
2. Refuse a second key, show an explained precondition failure with no destination, exercise schedule off/900 seconds/invalid bounds, and verify next-run scheduling uses the last attempt. Restore changed fixture settings afterwards.
3. Pair/deposit against a disposable TLS KyRecovery fixture, verify `service_name=KyBookmarks`, receipt digest and local-copy outcome. Restart using the same volume/key and deposit again without re-pairing.
4. Restore an exported capsule with synthetic shares on stdin into an empty target. Check database contents, required files, modes and restored pairing readability; boot only in an isolated environment. Exercise wrong service, insufficient/wrong shares, damaged capsule and nonempty target refusal. Follow the actual runbook commands, including Docker ownership and config placement, rather than relying only on a library round trip.

## 7. Actual deployment proof and completion

This stage needs deployment access and an agreed concrete deployment revision. The present request authorizes planning; do not change production as part of writing this plan. Prepare the tested artifact before any deployment approval needed in the execution session.

Preserve existing volumes, issuer configuration, deployment/audit keys and pairing. If already paired, deposit with that pairing; do not rotate or re-pair to make the proof pass. If never paired, label the evidence first-pair proof and obtain the ephemeral PIN out of band.

For the intended homelab, use `KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY=true`, `KYBOOKMARKS_DNS=192.168.1.1`, and `docker-compose.lan-dns.yml` with the base compose file. Source deployments require `up -d --build`. Verify container DNS, readiness and the actual deployed revision. HTTPS, redirect and loopback refusal remain enforced. The recovery URL is `https://kyrecovery.urlxl.us`; compare its public-key fingerprint out of band.

Record only nonsecret evidence: tested/deployed SHA or image digest, readiness, previous/current pinned key ID, capsule ID, SHA-256 digest, receipt timestamp, and local-copy result. Report code/CI completion, disposable restore proof, and actual deployment deposit as separate statuses. Real custodian-card restoration is a separate human exercise; shares stay on local stdin, never chat, argv, or the shared board.

## Next action and cautions

The next execution session starts at step 1 after checking the board. No implementation or tests have run for this plan. Do not restart the merged adoption, reuse another session's worktree, discard existing deployment state, or treat a KySignOn receipt as KyBookmarks proof. Mirror execution hand-offs and this plan verbatim to the same myslop folder; keep the durable copy in the repository because the board expires.
