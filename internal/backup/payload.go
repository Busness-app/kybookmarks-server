package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

// Member paths say where each file restores to: config/* into CONFIG_DIR, everything
// else into DATA_DIR.
const (
	dbMember       = "kybookmarks.db"
	ssoMember      = "config-sso/sso.json" // DATA_DIR/config/sso.json
	auditLogMember = "audit/audit.log"
	manifestMember = "manifest.json"
)

// required are the CONFIG_DIR files a restore cannot start without: the audit chain key and
// mark, the decoy-salt key, and the deployment key that opens the stored KyRecovery token.
var required = []string{"audit.key", "audit.state", "enum.key", "deployment.key"}

// Members lists what a capsule carries, in Collect's order, so the screen can say so
// without sealing anything.
func Members(dataDir, configDir string) []string {
	m := []string{dbMember}
	for _, f := range required {
		m = append(m, "config/"+f)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "config", "sso.json")); err == nil {
		m = append(m, ssoMember)
	}
	if _, err := os.Stat(recoveryclient.RecoveryKeyPath(dataDir)); err == nil {
		m = append(m, "recovery.pub")
	}
	return append(m, auditLogMember, manifestMember)
}

// Collect gathers everything a restore needs. A missing required key is fatal: a capsule that
// restores a server that refuses to start is worse than no capsule, because the drill passes.
func Collect(ctx context.Context, st *store.Store, dataDir, configDir, appVersion string) (recoveryclient.Payload, error) {
	var files []recoveryclient.File

	scratch, err := os.MkdirTemp(dataDir, "snapshot-*")
	if err != nil {
		return recoveryclient.Payload{}, err
	}
	defer os.RemoveAll(scratch)
	snap := filepath.Join(scratch, dbMember)
	if err := recoveryclient.SQLiteSnapshot(ctx, st.DB(), snap); err != nil {
		return recoveryclient.Payload{}, fmt.Errorf("database snapshot: %w", err)
	}
	db, err := os.ReadFile(snap)
	if err != nil || len(db) == 0 {
		return recoveryclient.Payload{}, errors.New("database snapshot is empty")
	}
	files = append(files, recoveryclient.File{Path: dbMember, Data: db, Mode: 0600})

	for _, name := range required {
		b, err := os.ReadFile(filepath.Join(configDir, name))
		if err != nil || len(b) == 0 {
			return recoveryclient.Payload{}, fmt.Errorf("backup requires %s: %w", name, err)
		}
		files = append(files, recoveryclient.File{Path: "config/" + name, Data: b, Mode: 0600})
	}
	if b, err := os.ReadFile(filepath.Join(dataDir, "config", "sso.json")); err == nil {
		files = append(files, recoveryclient.File{Path: ssoMember, Data: b, Mode: 0600})
	}
	if pub, err := os.ReadFile(recoveryclient.RecoveryKeyPath(dataDir)); err == nil {
		files = append(files, recoveryclient.File{Path: "recovery.pub", Data: pub, Mode: 0600})
	}
	auditLog, err := os.ReadFile(filepath.Join(dataDir, "audit", "audit.log"))
	if err != nil {
		return recoveryclient.Payload{}, fmt.Errorf("backup requires the audit log: %w", err)
	}
	files = append(files, recoveryclient.File{Path: auditLogMember, Data: auditLog, Mode: 0600})

	manifest, _ := json.Marshal(map[string]any{
		"service":     AppName,
		"app_version": appVersion,
		"restore":     "kybookmarks-server restore -capsule <file> -to <dir>; config/* go to CONFIG_DIR, config-sso/sso.json to DATA_DIR/config/, the rest to DATA_DIR",
	})
	files = append(files, recoveryclient.File{Path: manifestMember, Data: manifest, Mode: 0600})

	return recoveryclient.Payload{
		ServiceName:        AppName,
		AppVersion:         appVersion,
		Files:              files,
		Dependencies:       map[string]any{"sqlite": "modernc.org/sqlite", "go": "1.26"},
		VerificationRecipe: map[string]any{"required_tables": []string{"accounts", "vault_objects", "settings"}, "require_any_admin": true},
	}, nil
}
