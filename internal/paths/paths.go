package paths

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Storage constants define goLAN's default directory and environment override.
const (
	AppConfigDir  = "goLAN"
	EnvConfigDir  = "GOLAN_CONFIG_DIR"
	directoryMode = 0o700
	fileMode      = 0o600
)

// ConfigRoot returns the per-user config root, even when golan is run via sudo.
func ConfigRoot() (string, error) {
	if override := strings.TrimSpace(os.Getenv(EnvConfigDir)); override != "" {
		return validateConfigRoot(override)
	}
	home, err := invokingHome()
	if err != nil {
		return "", err
	}
	return validateConfigRoot(filepath.Join(home, ".config", AppConfigDir))
}

// ConfigDir returns the versioned snapshot directory beneath ConfigRoot.
func ConfigDir() (string, error) {
	root, err := ConfigRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "configs"), nil
}

// PcapRoot returns the per-user live-session artifact directory.
func PcapRoot() (string, error) {
	root, err := ConfigRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "pcaps"), nil
}

// PcapRunDir returns a new timestamped packet-capture directory.
func PcapRunDir() (string, error) {
	root, err := PcapRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, time.Now().Format("20060102-150405-000000000")), nil
}

// SafeFilenamePart converts an adapter, role, or artifact label into one path
// component. It never returns an empty, dot, or dot-dot component.
func SafeFilenamePart(value string) string {
	value = strings.TrimSpace(value)
	var out strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9', char == '-', char == '_', char == '.':
			out.WriteRune(char)
		default:
			out.WriteByte('_')
		}
	}
	name := strings.Trim(out.String(), ".")
	if name == "" {
		return "unknown"
	}
	return name
}

// WriteConfigArtifact atomically writes owner-only data beneath ConfigRoot.
// The rooted filesystem handle prevents a symlink inside the config tree from
// redirecting a privileged write outside that tree.
func WriteConfigArtifact(path string, content []byte) (err error) {
	rootPath, err := ConfigRoot()
	if err != nil {
		return err
	}
	relativePath, err := configRelativePath(rootPath, path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(rootPath, directoryMode); err != nil {
		return fmt.Errorf("create config root: %w", err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open config root: %w", err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close config root: %w", closeErr))
		}
	}()

	parent := filepath.Dir(relativePath)
	if err := root.MkdirAll(parent, directoryMode); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	temporaryPath, file, err := createTemporaryArtifact(root, parent, filepath.Base(relativePath))
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := root.Remove(temporaryPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temporary artifact: %w", removeErr))
		}
	}()

	if _, err := file.Write(content); err != nil {
		return errors.Join(fmt.Errorf("write temporary artifact: %w", err), closeArtifact(file, "temporary artifact"))
	}
	if err := file.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync temporary artifact: %w", err), closeArtifact(file, "temporary artifact"))
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary artifact: %w", err)
	}
	if err := root.Rename(temporaryPath, relativePath); err != nil {
		return fmt.Errorf("replace artifact: %w", err)
	}

	directory, err := root.Open(parent)
	if err != nil {
		return fmt.Errorf("open artifact directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync artifact directory: %w", err), closeArtifact(directory, "artifact directory"))
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close artifact directory: %w", err)
	}
	if err := finalizeConfigArtifact(root, relativePath); err != nil {
		return fmt.Errorf("finalize artifact permissions: %w", err)
	}
	return nil
}

func finalizeConfigArtifact(root *os.Root, relativePath string) error {
	owner, hasOwner := invokingOwner()
	var errs []error
	finalize := func(path string, mode fs.FileMode) {
		if err := root.Chmod(path, mode); err != nil {
			errs = append(errs, fmt.Errorf("chmod %s: %w", path, err))
		}
		if hasOwner {
			if err := root.Chown(path, owner.uid, owner.gid); err != nil {
				errs = append(errs, fmt.Errorf("chown %s: %w", path, err))
			}
		}
	}

	finalize(".", directoryMode)
	parent := filepath.Dir(relativePath)
	if parent != "." {
		current := ""
		for _, component := range strings.Split(parent, string(filepath.Separator)) {
			current = filepath.Join(current, component)
			finalize(current, directoryMode)
		}
	}
	finalize(relativePath, fileMode)
	return errors.Join(errs...)
}

// ReadConfigArtifact reads at most limit bytes from a file beneath ConfigRoot.
// It returns an error instead of following a symlink outside the rooted tree.
func ReadConfigArtifact(path string, limit int64) (content []byte, err error) {
	if limit < 0 || limit == math.MaxInt64 {
		return nil, fmt.Errorf("artifact read limit must be between 0 and %d", int64(math.MaxInt64-1))
	}
	rootPath, err := ConfigRoot()
	if err != nil {
		return nil, err
	}
	relativePath, err := configRelativePath(rootPath, path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open config root: %w", err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close config root: %w", closeErr))
		}
	}()
	file, err := root.Open(relativePath)
	if err != nil {
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	content, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("read artifact: %w", err), closeArtifact(file, "artifact"))
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close artifact: %w", err)
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("artifact exceeds %d bytes", limit)
	}
	return content, nil
}

// ListConfigArtifacts returns the regular, non-symlink entries in a directory
// beneath ConfigRoot. A missing config root or directory is an empty list.
func ListConfigArtifacts(path string) (names []string, err error) {
	rootPath, err := ConfigRoot()
	if err != nil {
		return nil, err
	}
	relativePath, err := configRelativePath(rootPath, path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open config root: %w", err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close config root: %w", closeErr))
		}
	}()
	directory, err := root.Open(relativePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open artifact directory: %w", err)
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("read artifact directory: %w", err), closeArtifact(directory, "artifact directory"))
	}
	if err := directory.Close(); err != nil {
		return nil, fmt.Errorf("close artifact directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect artifact %s: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		names = append(names, entry.Name())
	}
	return names, nil
}

func configRelativePath(rootPath, path string) (string, error) {
	absPath, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", fmt.Errorf("resolve artifact path: %w", err)
	}
	relativePath, err := filepath.Rel(rootPath, absPath)
	if err != nil {
		return "", fmt.Errorf("resolve artifact path relative to config root: %w", err)
	}
	if relativePath == "." || !filepath.IsLocal(relativePath) {
		return "", fmt.Errorf("artifact path must be a file beneath the config root")
	}
	return relativePath, nil
}

func createTemporaryArtifact(root *os.Root, parent, base string) (string, *os.File, error) {
	for range 10 {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", nil, fmt.Errorf("generate temporary artifact name: %w", err)
		}
		name := "." + base + ".tmp-" + hex.EncodeToString(suffix[:])
		path := filepath.Join(parent, name)
		file, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
		if err == nil {
			return path, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, fmt.Errorf("create temporary artifact: %w", err)
		}
	}
	return "", nil, fmt.Errorf("create temporary artifact: name collision limit reached")
}

func closeArtifact(file *os.File, description string) error {
	if file == nil {
		return nil
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", description, err)
	}
	return nil
}

// FinalizeTree applies invoking-user ownership and owner-only modes without following symlinks.
func FinalizeTree(root string) error {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve artifact root: %w", err)
	}
	absRoot = filepath.Clean(absRoot)
	if isFilesystemRoot(absRoot) {
		return fmt.Errorf("refuse to finalize filesystem root %q", absRoot)
	}

	owner, hasOwner := invokingOwner()
	var errs []error
	err = filepath.WalkDir(absRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			errs = append(errs, walkErr)
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		mode := fs.FileMode(fileMode)
		if entry.IsDir() {
			mode = directoryMode
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

func validateConfigRoot(value string) (string, error) {
	root, err := filepath.Abs(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("resolve config root: %w", err)
	}
	root = filepath.Clean(root)
	if isFilesystemRoot(root) {
		return "", fmt.Errorf("config root must not be a filesystem root")
	}
	return root, nil
}

func isFilesystemRoot(path string) bool {
	volume := filepath.VolumeName(path)
	return path == string(filepath.Separator) || path == volume+string(filepath.Separator)
}

func invokingHome() (string, error) {
	if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
		u, err := user.Lookup(sudoUser)
		if err != nil {
			return "", fmt.Errorf("lookup invoking user %q: %w", sudoUser, err)
		}
		if strings.TrimSpace(u.HomeDir) == "" {
			return "", fmt.Errorf("invoking user %q has no home directory", sudoUser)
		}
		return u.HomeDir, nil
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
