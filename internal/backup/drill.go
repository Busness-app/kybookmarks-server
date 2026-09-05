package backup

import (
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	_ "modernc.org/sqlite"
)

var requiredTables = []string{"accounts", "vault_objects", "settings"}

// Checks validates the manifest that was actually opened, including JSON-decoded recipe
// values. A recipe may add requirements, but cannot weaken the product's restore baseline.
func Checks(dir string, opened capsule.Manifest) []recoveryclient.Check {
	var out []recoveryclient.Check
	add := func(name string, ok bool, msg string) {
		out = append(out, recoveryclient.Check{Name: name, Passed: ok, Message: msg})
	}
	add("Service", opened.ServiceName == AppName, opened.ServiceName)
	tables := append([]string(nil), requiredTables...)
	recipe, ok := opened.VerificationRecipe.(map[string]any)
	add("Verification recipe", ok, "expected an object")
	declared := map[string]bool{}
	list, ok := recipe["required_tables"].([]any)
	add("Required tables recipe", ok && len(list) > 0, "expected a nonempty list of table names")
	for _, value := range list {
		table, ok := value.(string)
		ok = ok && strings.TrimSpace(table) != "" && !strings.ContainsRune(table, '\x00')
		add("Table recipe entry", ok, "expected a nonempty table name")
		if ok && !declared[table] {
			declared[table] = true
			tables = append(tables, table)
		}
	}
	for _, table := range requiredTables {
		add("Recipe requires: "+table, declared[table], "required by KyBookmarks")
	}
	admin, ok := recipe["require_any_admin"].(bool)
	add("Administrator recipe", ok && admin, "require_any_admin must be true")

	root, err := os.OpenRoot(dir)
	if err != nil {
		add("Scratch directory", false, err.Error())
		return out
	}
	defer root.Close()
	members := map[string]bool{}
	dbPresent := false
	for _, f := range opened.Files {
		valid := fs.ValidPath(f.Path) && f.Path != "." && !strings.ContainsAny(f.Path, "\\:\x00")
		add("Member path: "+f.Path, valid, "expected a clean relative capsule path")
		if !valid {
			continue
		}
		members[f.Path] = true
		// OpenRoot confines all member lookups, including intermediate symlinks. The database
		// itself must not be a symlink because SQLite opens its fixed path separately below.
		info, err := root.Lstat(f.Path)
		regular := err == nil && info.Mode().IsRegular()
		if regular {
			file, openErr := root.Open(f.Path)
			err = openErr
			if err == nil {
				err = file.Close()
			}
		}
		label := "Member present: " + f.Path
		if f.Path == dbMember {
			label = "Database present: " + dbMember
			dbPresent = regular && err == nil
		}
		add(label, regular && err == nil, errText(err))
	}
	core := []string{dbMember, auditLogMember, manifestMember}
	for _, name := range required {
		core = append(core, "config/"+name)
	}
	for _, name := range core {
		add("Required member: "+name, members[name], "required by KyBookmarks")
	}
	if !dbPresent {
		return out
	}

	abs, err := filepath.Abs(filepath.Join(dir, dbMember))
	if err != nil {
		add("Database opens", false, err.Error())
		return out
	}
	uri := url.URL{Scheme: "file", Path: abs, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		add("Database opens", false, err.Error())
		return out
	}
	defer db.Close()
	var integrity string
	err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	add("Database integrity", err == nil && integrity == "ok", integrity+errText(err))
	checked := map[string]bool{}
	for _, table := range tables {
		if checked[table] {
			continue
		}
		checked[table] = true
		var n int
		err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n)
		add("Table present: "+table, err == nil && n == 1, errText(err))
	}
	var admins int
	err = db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE role='admin' AND status='active'`).Scan(&admins)
	add("Active administrator", err == nil && admins > 0, fmt.Sprintf("%d active administrator(s)%s", admins, errText(err)))
	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
