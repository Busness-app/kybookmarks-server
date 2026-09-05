package backup

import (
	"context"
	"fmt"

	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kybookmarks-server/internal/store"
)

// RunDrill serializes HTTP and CLI drills against the same scratch root before collecting
// or sweeping. The library owns the throwaway key and all cleartext extraction/cleanup.
func RunDrill(ctx context.Context, st *store.Store, dataDir, configDir, appVersion string) (*recoveryclient.DrillResult, error) {
	root, err := DrillRoot(dataDir)
	if err != nil {
		return nil, err
	}
	lock, err := lockDrill(root)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	payload, err := Collect(ctx, st, dataDir, configDir, appVersion)
	if err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}
	return recoveryclient.Drill(ctx, root, payload, Checks)
}
