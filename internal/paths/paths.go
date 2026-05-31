package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	AppConfigDir = "goLAN"
	EnvConfigDir = "GOLAN_CONFIG_DIR"
)

// ConfigRoot returns the per-user config root, even when golan is run via sudo.
func ConfigRoot() (string, error) {
	if override := strings.TrimSpace(os.Getenv(EnvConfigDir)); override != "" {
		return override, nil
	}
	home, err := invokingHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", AppConfigDir), nil
}

func ConfigDir() (string, error) {
	root, err := ConfigRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "configs"), nil
}

func PcapRunDir() (string, error) {
	root, err := ConfigRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "pcaps", time.Now().Format("20060102-150405-000000000")), nil
}

func FinalizeTree(root string) error {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil
	}
	owner, hasOwner := invokingOwner()
	var errs []error
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			errs = append(errs, walkErr)
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		mode := fs.FileMode(0o644)
		if entry.IsDir() {
			mode = 0o755
		}
		if err := os.Chmod(path, mode); err != nil {
			errs = append(errs, fmt.Errorf("chmod %s: %w", path, err))
		}
		if hasOwner {
			if err := os.Chown(path, owner.uid, owner.gid); err != nil {
				errs = append(errs, fmt.Errorf("chown %s: %w", path, err))
			}
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func invokingHome() (string, error) {
	if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
		if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
			return u.HomeDir, nil
		}
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" && home != "/var/root" && home != "/root" {
		return home, nil
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return home, nil
}

type ownerIDs struct {
	uid int
	gid int
}

func invokingOwner() (ownerIDs, bool) {
	if uid, uidOK := parseEnvID("SUDO_UID"); uidOK {
		if gid, gidOK := parseEnvID("SUDO_GID"); gidOK {
			return ownerIDs{uid: uid, gid: gid}, true
		}
	}
	if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
		if u, err := user.Lookup(sudoUser); err == nil {
			uid, uidErr := strconv.Atoi(u.Uid)
			gid, gidErr := strconv.Atoi(u.Gid)
			if uidErr == nil && gidErr == nil {
				return ownerIDs{uid: uid, gid: gid}, true
			}
		}
	}
	return ownerIDs{}, false
}

func parseEnvID(name string) (int, bool) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return 0, false
	}
	id, err := strconv.Atoi(value)
	if err != nil || id < 0 {
		return 0, false
	}
	return id, true
}
