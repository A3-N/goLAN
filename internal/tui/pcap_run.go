package tui

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PcapRun is the only persisted run artifact. It owns the timestamped
// directory where passive packet captures are written.
type PcapRun struct {
	Timestamp string
	Dir       string
}

func NewPcapRun() *PcapRun {
	stamp := time.Now().Format("20060102-150405-000000000")
	dir := filepath.Join(configRootDir(), "pcaps", stamp)
	_ = os.MkdirAll(dir, 0o700)
	return &PcapRun{
		Timestamp: stamp,
		Dir:       dir,
	}
}

func (p *PcapRun) PcapDir() string {
	if p == nil {
		return ""
	}
	return p.Dir
}

func (p *PcapRun) Files() []string {
	if p == nil || strings.TrimSpace(p.Dir) == "" {
		return nil
	}
	entries, err := os.ReadDir(p.Dir)
	if err != nil {
		return nil
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".pcap") {
			continue
		}
		files = append(files, filepath.Join(p.Dir, entry.Name()))
	}
	sort.Strings(files)
	return files
}

func (p *PcapRun) FinalizePermissions() error {
	if p == nil || strings.TrimSpace(p.Dir) == "" {
		return nil
	}

	uid, gid, haveOwner := invokingUserIDs()
	var errs []string
	chownPath := func(path string) {
		if !haveOwner || os.Geteuid() != 0 {
			return
		}
		if err := os.Chown(path, uid, gid); err != nil {
			errs = append(errs, fmt.Sprintf("chown %s: %v", path, err))
		}
	}
	chmodPath := func(path string, mode os.FileMode) {
		if err := os.Chmod(path, mode); err != nil {
			errs = append(errs, fmt.Sprintf("chmod %s: %v", path, err))
		}
	}

	for _, dir := range []string{configRootDir(), filepath.Join(configRootDir(), "pcaps"), p.Dir} {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			chownPath(dir)
			chmodPath(dir, 0o755)
		}
	}

	err := filepath.WalkDir(p.Dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			errs = append(errs, fmt.Sprintf("walk %s: %v", path, walkErr))
			return nil
		}
		chownPath(path)
		if entry.IsDir() {
			chmodPath(path, 0o755)
			return nil
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".pcap") {
			chmodPath(path, 0o644)
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, " | "))
	}
	return nil
}

func NukePcaps() (string, error) {
	root := filepath.Join(configRootDir(), "pcaps")
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("pcap config root is empty")
	}
	return root, os.RemoveAll(root)
}

func invokingUserIDs() (int, int, bool) {
	if uid, gid, ok := sudoEnvIDs(); ok {
		return uid, gid, true
	}
	sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER"))
	if sudoUser == "" || sudoUser == "root" {
		return 0, 0, false
	}
	account, err := user.Lookup(sudoUser)
	if err != nil {
		return 0, 0, false
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid == 0 {
		return 0, 0, false
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return 0, 0, false
	}
	return uid, gid, true
}

func sudoEnvIDs() (int, int, bool) {
	uidText := strings.TrimSpace(os.Getenv("SUDO_UID"))
	gidText := strings.TrimSpace(os.Getenv("SUDO_GID"))
	if uidText == "" || gidText == "" {
		return 0, 0, false
	}
	uid, err := strconv.Atoi(uidText)
	if err != nil || uid == 0 {
		return 0, 0, false
	}
	gid, err := strconv.Atoi(gidText)
	if err != nil {
		return 0, 0, false
	}
	return uid, gid, true
}

func configRootDir() string {
	if override := strings.TrimSpace(os.Getenv("GOLAN_CONFIG_DIR")); override != "" {
		return override
	}
	if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
		if account, err := user.Lookup(sudoUser); err == nil && strings.TrimSpace(account.HomeDir) != "" {
			return filepath.Join(account.HomeDir, ".config", "goLAN")
		}
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".config", "goLAN")
	}
	if dir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(dir) != "" {
		return filepath.Join(dir, "goLAN")
	}
	return filepath.Join(".config", "goLAN")
}
