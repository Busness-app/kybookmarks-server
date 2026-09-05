//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package backup

import (
	"errors"
	"os"
)

func lockDrill(string) (*os.File, error) {
	return nil, errors.New("backup drill locking is unsupported on this platform")
}
