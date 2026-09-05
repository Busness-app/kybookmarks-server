package backup

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	_ "modernc.org/sqlite"
)

// Checks judge an opened capsule: every member present, the database passes integrity_check,
// the required tables exist, and at least one active admin can log in afterwards.
func Checks(payload recoveryclient.Payload) func(dir string) []recoveryclient.Check {
	return func(dir string) []recoveryclient.Check {
		var out []recoveryclient.Check
		add := func(name string, ok bool, msg string) {
			out = append(out, recoveryclient.Check{Name: name, Passed: ok, Message: msg})
		}
		for _, f := range payload.Files {
			_, err := os.Stat(filepath.Join(dir, f.Path))
			label := "Member present: " + f.Path
			if f.Path == dbMember {
				label = "Database present: " + dbMember
			}
			add(label, err == nil, errText(err))
		}
		db, err := sql.Open("sqlite", filepath.Join(dir, dbMember)+"?mode=ro")
		if err != nil {
			add("Database opens", false, err.Error())
			return out
		}
		defer db.Close()
		var integrity string
		err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
		add("Database integrity", err == nil && integrity == "ok", integrity+errText(err))
		for _, table := range []string{"accounts", "vault_objects", "settings"} {
			var n int
			err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n)
			add("Table present: "+table, err == nil && n == 1, errText(err))
		}
		var admins int
		err = db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE role='admin' AND status='active'`).Scan(&admins)
		add("Active administrator", err == nil && admins > 0, fmt.Sprintf("%d active administrator(s)%s", admins, errText(err)))
		return out
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
