"""Ablation suite for the audit chain, the directory-sync webhook and access control.

Breaks each defence in turn and asserts that some test notices. A test that still
passes with the defence removed is not testing the defence. Run from the repo root."""

import os
import shutil
import subprocess

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

AUDIT = "internal/audit/audit.go"
ADMIN = "internal/api/admin_handlers.go"
SERVER = "internal/api/server.go"
AUTH = "internal/api/auth_handlers.go"
DEVICEH = "internal/api/device_handlers.go"
DEVICES = "internal/devices/devices.go"
STORE = "internal/store/store.go"

BACKUP = ".ablate.bak"

ABLATIONS = [
 ("constant key fallback", AUDIT, "TestKeyIsNotAConstant|TestForgery",
  "\treturn keyfile.LoadOrCreate(filepath.Join(configDir, keyFile), keyLen)",
  "\treturn []byte(legacyDefaultSecret + legacyDefaultSecret)[:keyLen], nil"),

 ("anchor taken from the log instead of the mark", AUDIT, "TestTruncation|TestMissingState",
  "\tif err := auditchain.Verify(l.key, records, l.anchor); err != nil {",
  "\tanchor := l.anchor\n\tif len(records) > 0 {\n\t\tanchor = auditchain.Anchor{Count: uint64(len(records)), Hash: records[len(records)-1].Hash}\n\t}\n\tif err := auditchain.Verify(l.key, records, anchor); err != nil {"),

 ("high-water mark may drop", AUDIT, "TestTruncation|TestHighWaterMark",
  "\tif st != nil && uint64(st.Count) > l.anchor.Count {\n\t\treturn nil\n\t}", "\t_ = st"),

 ("emptied log skips the truncation check", AUDIT, "TestEmptyOrCorruptLogWithAMarkIsRefused",
  "\tif uint64(len(entries)) < l.anchor.Count {",
  "\tif false && uint64(len(entries)) < l.anchor.Count {"),

 ("missing mark accepted instead of refused", AUDIT, "TestMissingState",
  "\tif st == nil && len(entries) > 0 && l.anchor.Count == 0 {",
  "\tif false && st == nil && len(entries) > 0 && l.anchor.Count == 0 {"),

 ("mark never catches up after an interrupted write", AUDIT, "TestStateCatchesUp|TestTruncation",
  "\toverrun := l.anchor.Count > 0 && uint64(len(entries)) > l.anchor.Count",
  "\toverrun := false && l.anchor.Count > 0 && uint64(len(entries)) > l.anchor.Count"),

 ("audit write cancellable by the client", AUDIT, "TestAbortedRequestStillAudits",
  "\tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appendTimeout)",
  "\tctx, cancel := context.WithTimeout(ctx, appendTimeout)"),

 ("audit deadline started before the mutex it cannot interrupt", AUDIT, "TestHungStoreDelays",
  "\t// budget measured from the moment it can actually make progress.\n\tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appendTimeout)\n\tdefer cancel()\n",
  "\t// budget measured from the moment it can actually make progress.\n",
  "(Entry, error) {\n\tl.mu.Lock()",
  "(Entry, error) {\n\tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appendTimeout)\n\tdefer cancel()\n\tl.mu.Lock()"),

 ("chain driven from a second call site", AUDIT, "TestChainIsDrivenFromOneCallSite",
  "\tl.count++\n\tif stateErr != nil {", "\t_ = l.chain.Anchor()\n\tl.count++\n\tif stateErr != nil {"),

 ("a failed mark write stops the chain", AUDIT, "TestUnwritableMarkDoesNotForkTheChain",
  "\t\t\tstateErr = l.saveState()", "\t\t\treturn l.saveState()"),

 ("overrun run not checked against its predecessors", AUDIT, "TestOverrunRunMustChain",
  "\t\t\tif rec.Prev != prev {", "\t\t\tif false && rec.Prev != prev {"),

 ("non-atomic state write", AUDIT, "TestStateIsReplaced|TestVerifyChainIsNotRaced",
  "\treturn writeFileAtomic(l.statePath, data)", "\treturn os.WriteFile(l.statePath, data, 0600)"),

 ("converge trusts the log instead of the mark", AUDIT, "TestForgedLegacyLog",
  "\t} else if st.Count != len(entries) || st.Hash != entries[len(entries)-1].Hash {",
  "\t} else if false {"),

 ("converge checks the mark's count but not its tail hash", AUDIT, "TestForgedLegacyLog",
  "\t} else if st.Count != len(entries) || st.Hash != entries[len(entries)-1].Hash {",
  "\t} else if st.Count < len(entries) {"),

 ("converge blesses a log that verifies under neither digest", AUDIT, "TestConvergeRefuses|TestForgedLegacyLog|TestLegacyLog",
  "\tversions, ok := l.legacyVersions(entries)\n\tif !ok {\n\t\treturn entries, nil\n\t}",
  "\tversions, _ := l.legacyVersions(entries)"),

 ("legacy version ignored when recognising entries", AUDIT, "TestLegacyLog|TestForgery|TestKeyIsNotAConstant",
  "\tif version == version0 {\n\t\treturn chainHash(l.legacyKey,",
  "\tif false {\n\t\treturn chainHash(l.legacyKey,"),

 ("torn tail merged into the next record", AUDIT, "TestTornWrite",
  "\t\tline := append(data, '\\n')\n\t\tif l.tornTail {",
  "\t\tline := append(data, '\\n')\n\t\tif false && l.tornTail {"),

 ("torn tail never noticed, so the next append merges onto it", AUDIT, "TestTornWrite",
  "\tsc.torn = len(data) > 0 && data[len(data)-1] != '\\n'",
  "\tsc.torn = false"),

 ("a corrupt line is reported as a removed record", AUDIT, "TestCorruptLineIsNotReportedAsTruncation",
  "\tif uint64(len(entries)) < l.anchor.Count && sc.corrupt > 0 {",
  "\tif false && uint64(len(entries)) < l.anchor.Count && sc.corrupt > 0 {"),

 ("undecodable lines counted as absent records", AUDIT, "TestCorruptLineIsNotReportedAsTruncation|TestEmptyOrCorrupt",
  "\t\t\tsc.corrupt++\n\t\t\tcontinue",
  "\t\t\tcontinue"),

 ("overrun records not verified against the key", AUDIT, "TestOverrunRecordsMustCarryTheirOwnDigest|TestOverrunIsNotAdopted",
  "\t\t\tif err := auditchain.VerifyRecord(l.key, rec); err != nil {",
  "\t\t\tif err := error(nil); err != nil {"),

 ("a failed write leaves the chain describing a log it no longer matches", AUDIT,
  "TestShortWrite|TestFailedWriteReconciles",
  "\t\t\tl.stale = true\n\t\t\treturn err", "\t\t\treturn err"),

 ("the chain is never rebuilt from the log after a failed write", AUDIT,
  "TestShortWrite|TestFailedWriteReconciles",
  "\tif l.stale {\n\t\tif err := l.recover(); err != nil {",
  "\tif false && l.stale {\n\t\tif err := l.recover(); err != nil {"),

 ("degraded health answers 503", AUTH, "TestDegradedHealthStaysHTTP200",
  '\twriteJSON(w, http.StatusOK, map[string]any{\n\t\t"status":  status,',
  '\tcode := http.StatusOK\n\tif status == "degraded" {\n\t\tcode = http.StatusServiceUnavailable\n\t}\n\twriteJSON(w, code, map[string]any{\n\t\t"status":  status,'),

 ("health hands the failure count to anyone who asks", AUTH, "TestAuditWriteFailureIsNotSilent",
  '\t\t"service": "kybookmarks-server",\n\t\t"time":    time.Now().UTC(),',
  '\t\t"service": "kybookmarks-server",\n\t\t"auditWriteFailures": s.auditFailures.Load(),\n\t\t"time":    time.Now().UTC(),'),

 ("a failed audit write is discarded again", SERVER, "TestAuditWriteFailureIsNotSilent",
  "\t_, err := s.audit.Log(r.Context(), action, userID, deviceID, clientIP(r), details)\n\tif err == nil {",
  "\t_, _ = s.audit.Log(r.Context(), action, userID, deviceID, clientIP(r), details)\n\terr := error(nil)\n\tif err == nil {"),

 ("a lagging mark is reported as a missing record", SERVER, "TestUnwritableMarkIsNotReportedAsAMissingRecord",
  "\tif errors.Is(err, audit.ErrMarkNotAdvanced) {",
  "\tif errors.Is(err, audit.ErrMarkNotAdvanced) && false {"),

 ("sync signature optional again", SERVER, "TestDirectorySync",
  '\tmux.Handle("POST /api/sync/events", s.syncAuth()(http.HandlerFunc(s.handleDirectorySyncEvent)))',
  '\tmux.HandleFunc("POST /api/sync/events", s.handleDirectorySyncEvent)'),

 ("pair/request public again", SERVER, "TestPairRequestRequiresAuth|TestPairingCannotEscalate",
  '\tmux.HandleFunc("POST /api/devices/pair/request", s.withAuth(s.handlePairRequest))',
  '\tmux.HandleFunc("POST /api/devices/pair/request", s.handlePairRequest)'),

 ("pairing trusts the body userId", DEVICEH, "TestPairRequestIgnoresBodyUserID|TestPairingCannotEscalate",
  "\tvar req struct {\n\t\tDeviceName string `json:\"deviceName\"`",
  "\tvar req struct {\n\t\tUserID     string `json:\"userId\"`\n\t\tDeviceName string `json:\"deviceName\"`",
  "\tsess, err := s.devices.RequestPairing(acc.ID, req.DeviceName, req.DeviceType)",
  "\tif req.UserID != \"\" {\n\t\tacc.ID = req.UserID\n\t}\n\tsess, err := s.devices.RequestPairing(acc.ID, req.DeviceName, req.DeviceType)"),

 ("approval not scoped to the owner", DEVICES, "TestApprovalCannotCross|TestPairingCannotEscalate",
  "\t\tWHERE pin = ? AND user_id = ? AND expires_at > ? AND approved = 0`\n\tres, err := s.db.Exec(query, vaultKeyEnvelope, pin, userID, now)",
  "\t\tWHERE pin = ? AND (user_id = ? OR 1=1) AND expires_at > ? AND approved = 0`\n\tres, err := s.db.Exec(query, vaultKeyEnvelope, pin, userID, now)"),

 ("setup re-check dropped", AUTH, "TestSetupCannotEnrolTwoAdmins",
  "\tif err := s.store.CreateFirstAdmin(admin); err != nil {",
  "\tif err := s.store.CreateAccount(admin); err != nil {"),

 ("recovery ignores suspension", AUTH, "TestRecoveryRefusesSuspendedAccount",
  '\tif acc.Status != "active" {\n\t\ts.auditEvent(r, "auth.recovery_failed"',
  '\tif false {\n\t\ts.auditEvent(r, "auth.recovery_failed"'),

 ("recovery unmetered", AUTH, "TestRecoveryLocksOut",
  '\tif exists && time.Now().Before(tracker.blockedUntil) {\n\t\ts.loginAttemptsMu.Unlock()\n\t\ts.auditEvent(r, "auth.recovery_blocked"',
  '\tif false && exists && time.Now().Before(tracker.blockedUntil) {\n\t\ts.loginAttemptsMu.Unlock()\n\t\ts.auditEvent(r, "auth.recovery_blocked"'),

 ("constant decoy salt", AUTH, "TestLoginParamsDoesNotReveal",
  '\t\t\t"salt":       hex.EncodeToString(mac.Sum(nil)[:16]),',
  '\t\t\t"salt":       "0123456789abcdef0123456789abcdef",'),

 ("csrf compared to the cookie", SERVER, "TestCSRFTokenMustMatchTheSession",
  '\tif sess == nil || sess.CSRFToken == "" {\n\t\treturn false\n\t}\n\n\theaderToken := r.Header.Get("X-CSRF-Token")\n\treturn headerToken != "" && hmac.Equal([]byte(headerToken), []byte(sess.CSRFToken))',
  '\tcookie, err := r.Cookie(csrfCookieName)\n\tif err != nil || cookie.Value == "" {\n\t\treturn false\n\t}\n\n\theaderToken := r.Header.Get("X-CSRF-Token")\n\treturn headerToken != "" && hmac.Equal([]byte(headerToken), []byte(cookie.Value))'),

 ("sso adopts on any email claim", AUTH, "TestSSOWillNotAdopt",
  "if user == nil && claims.EmailVerified && strings.Contains(claims.Email, \"@\") {",
  "if user == nil && strings.Contains(claims.Email, \"@\") {"),

 ("sso adopts a suspended account", AUTH, "TestSSOWillNotBindASuspendedAccount",
  '\t\t\tif existing.Status != "active" {\n\t\t\t\thttp.Error(w, "account is suspended", http.StatusForbidden)',
  '\t\t\tif false {\n\t\t\t\thttp.Error(w, "account is suspended", http.StatusForbidden)'),

 ("sso rebinds a linked account", AUTH, "TestSSOWillNotRebindALinkedAccount",
  '\t\t\tif existing.SSOSubject != "" {', '\t\t\tif false {'),

 ("sso subject collides on empty string", STORE, "TestSecondAccountCanBeCreated|TestSSOWillNotAdopt",
  "\tif s == \"\" {\n\t\treturn nil\n\t}\n\treturn s\n}",
  "\treturn s\n}"),
]


fail = False
for name, path, tests, *edits in ABLATIONS:
    src = open(path).read()
    patched, missed = src, False
    for old, new in zip(edits[::2], edits[1::2]):
        if old not in patched:
            missed = True
            break
        patched = patched.replace(old, new, 1)
    if missed:
        print(f"{name}: PATCH DID NOT MATCH -- ablation not applied"); fail = True; continue
    shutil.copy(path, BACKUP)
    open(path, "w").write(patched)
    try:
        b = subprocess.run(["go", "build", "./..."], capture_output=True, text=True)
        if b.returncode != 0:
            print(f"{name}: ABLATION DID NOT COMPILE -- {b.stderr.strip().splitlines()[:1]}"); fail = True; continue
        t = subprocess.run(["go", "test", "-count=1", "./internal/...", "-run", tests],
                           capture_output=True, text=True)
        if t.returncode == 0:
            print(f"{name}: TESTS STILL PASS  <-- no test detects this"); fail = True
        else:
            n = t.stdout.count("--- FAIL")
            print(f"{name}: caught ({n} failing test(s))")
    finally:
        shutil.copy(BACKUP, path)

if os.path.exists(BACKUP):
    os.remove(BACKUP)
print("RESULT:", "SOME ABLATIONS SURVIVED" if fail else "every ablation caught")
raise SystemExit(1 if fail else 0)
