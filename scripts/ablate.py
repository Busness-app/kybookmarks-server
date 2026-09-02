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
  "\tkey := make([]byte, keyLen)\n\tif _, err := rand.Read(key); err != nil {",
  "\tkey := []byte(legacyDefaultSecret + legacyDefaultSecret)\n\tif _, err := rand.Read(make([]byte, 1)); err != nil {"),

 ("no truncation state check", AUDIT, "TestTruncation|TestMissingState",
  "\tcase st == nil && len(entries) > 0:", "\tcase false:"),

 ("high-water mark may drop", AUDIT, "TestTruncation|TestHighWaterMark",
  "\tif st != nil && st.Count > l.count {\n\t\treturn nil\n\t}", "\t_ = st"),

 ("self-heal missing state", AUDIT, "TestMissingState",
  "\t\t\tl.stateMissing = true\n\t\t\treturn nil", "\t\t\treturn l.saveState()"),

 ("state recreated by append", AUDIT, "TestMissingState",
  "\tif l.stateMissing {\n\t\treturn nil\n\t}\n", ""),

 ("mark never catches up after an interrupted write", AUDIT, "TestStateCatchesUp|TestTruncation",
  "\t\tl.count = st.Count\n\t\tif len(entries) > l.count {\n\t\t\tl.count = len(entries)\n\t\t}",
  "\t\tl.count = st.Count"),

 ("non-atomic state write", AUDIT, "TestStateIsReplaced|TestVerifyChainIsNotRaced",
  "\treturn writeFileAtomic(l.statePath, data)", "\treturn os.WriteFile(l.statePath, data, 0600)"),

 ("no legacy anchor marker", AUDIT, "TestLegacyLog",
  '\t\tif _, err := l.Log(actionRekeyed, "", "", "", "audit chain re-keyed; entries above this marker are legacy"); err != nil {\n\t\t\treturn fmt.Errorf("failed to anchor legacy audit chain: %w", err)\n\t\t}\n\t\treturn nil',
  "\t\treturn l.saveState()"),

 ("version ignored in hash", AUDIT, "TestLegacyLog|TestForgery|TestKeyIsNotAConstant",
  "\tif e.V == version0 {\n\t\treturn chainHash(l.legacyKey,", "\tif true {\n\t\treturn chainHash(l.legacyKey,"),

 ("sync signature optional again", ADMIN, "TestDirectorySync",
  '\tif s.cfg.SyncSecret == "" {\n\t\thttp.Error(w, `{"error":"sync_not_configured"}`, http.StatusUnauthorized)\n\t\treturn\n\t}\n\tmac := hmac.New',
  '\tif s.cfg.SyncSecret == "" || r.Header.Get("X-KySignOn-Signature") == "" {\n\t\twriteJSON(w, http.StatusOK, map[string]bool{"ok": true})\n\t\treturn\n\t}\n\tmac := hmac.New'),

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
  '\tif acc.Status != "active" {\n\t\t_, _ = s.audit.Log("auth.recovery_failed"',
  '\tif false {\n\t\t_, _ = s.audit.Log("auth.recovery_failed"'),

 ("recovery unmetered", AUTH, "TestRecoveryLocksOut",
  '\tif exists && time.Now().Before(tracker.blockedUntil) {\n\t\ts.loginAttemptsMu.Unlock()\n\t\t_, _ = s.audit.Log("auth.recovery_blocked"',
  '\tif false && exists && time.Now().Before(tracker.blockedUntil) {\n\t\ts.loginAttemptsMu.Unlock()\n\t\t_, _ = s.audit.Log("auth.recovery_blocked"'),

 ("constant decoy salt", AUTH, "TestLoginParamsDoesNotReveal",
  '\t\t\t"salt":       hex.EncodeToString(mac.Sum(nil)[:16]),',
  '\t\t\t"salt":       "0123456789abcdef0123456789abcdef",'),

 ("csrf compared to the cookie", SERVER, "TestCSRFTokenMustMatchTheSession",
  '\tif sess == nil || sess.CSRFToken == "" {\n\t\treturn false\n\t}\n\n\theaderToken := r.Header.Get("X-CSRF-Token")\n\treturn headerToken != "" && hmac.Equal([]byte(headerToken), []byte(sess.CSRFToken))',
  '\tcookie, err := r.Cookie(csrfCookieName)\n\tif err != nil || cookie.Value == "" {\n\t\treturn false\n\t}\n\n\theaderToken := r.Header.Get("X-CSRF-Token")\n\treturn headerToken != "" && hmac.Equal([]byte(headerToken), []byte(cookie.Value))'),

 ("sso adopts on any email claim", AUTH, "TestSSOWillNotAdopt",
  "\tif user == nil && claims.EmailVerified && claims.Email != \"\" {",
  "\tif user == nil && claims.Email != \"\" {"),

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
