// Package backup is what is specific to KyBookmarks in the suite's backup contract: what a
// capsule carries, how the drill judges a restore, and the adapters that bind this store
// and this deployment key to ky-primitives/recoveryclient. Pairing, key pin, schedule,
// local copies, deposit, drill mechanics and restore are the lib's.
package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

// AppName is the service name KyRecovery pins at pairing; every capsule must carry it.
const AppName = "KyBookmarks"

const tokenLabel = "kybookmarks:setting:kyrecovery_token"

type settings struct{ s *store.Store }

// Settings binds the store's settings rows to the lib, mapping not-found onto its error.
func Settings(s *store.Store) recoveryclient.Settings { return settings{s} }

func (a settings) Get(key string) (string, error) {
	v, err := a.s.GetSetting(key)
	if errors.Is(err, store.ErrNotFound) {
		return "", recoveryclient.ErrNotFound
	}
	return v, err
}
func (a settings) Set(key, value string) error { return a.s.SetSetting(key, value) }
func (a settings) Delete(key string) error     { return a.s.DeleteSetting(key) }

// NewSealer seals the KyRecovery token under the deployment key, domain-separated so a row
// copied from another setting will not open.
func NewSealer(deploymentKey []byte) (recoveryclient.Sealer, error) {
	return recoveryclient.NewAESGCMSealer(deploymentKey, tokenLabel)
}

// RunConfig is what recoveryclient.Run needs from this product.
func RunConfig(dataDir, backupDir string, keep int, appVersion string, sealer recoveryclient.Sealer) recoveryclient.RunConfig {
	return recoveryclient.RunConfig{DataDir: dataDir, AppName: AppName, AppVersion: appVersion,
		BackupDir: backupDir, Keep: keep, Sealer: sealer}
}

// AuditDetails flattens the lib's details into the audit line: sorted keys, bounded,
// printable. The audit chain stores one string.
func AuditDetails(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%v", k, m[k])
	}
	return recoveryclient.AuditSafe(b.String())
}

// DrillRoot is under the data directory, never the system temp dir: the opened payload is
// the whole instance in the clear. The lib opens each drill in a fresh 0700 subdirectory
// and expects the root to exist, so this creates it.
func DrillRoot(dataDir string) (string, error) {
	root := filepath.Join(dataDir, "drill")
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", fmt.Errorf("drill root: %w", err)
	}
	return root, nil
}
