"""Ablation suite for the audit chain and the directory-sync webhook.

Breaks each defence in turn and asserts that some test notices. A test that still
passes with the defence removed is not testing the defence. Run from the repo root."""

import os
import shutil
import subprocess

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

AUDIT = "internal/audit/audit.go"
ADMIN = "internal/api/admin_handlers.go"

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
]

fail = False
for name, path, tests, old, new in ABLATIONS:
    src = open(path).read()
    if old not in src:
        print(f"{name}: PATCH DID NOT MATCH -- ablation not applied"); fail = True; continue
    shutil.copy(path, BACKUP)
    open(path, "w").write(src.replace(old, new, 1))
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
