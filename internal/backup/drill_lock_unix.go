//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"golang.org/x/sys/unix"
)

// The lock file is permanent: unlinking it lets a contender lock a different inode.
// Closing the descriptor releases the advisory lock, including after a process crash.
func lockDrill(root string) (*os.File, error) {
	fd, err := unix.Open(filepath.Join(root, ".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("drill lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), "drill lock")
	if err = file.Chmod(0600); err == nil {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, recoveryclient.ErrInProgress
		}
		return nil, fmt.Errorf("drill lock: %w", err)
	}
	return file, nil
}
