//go:build darwin

package bridgefilter

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	bridgeGetFilterFlags = 23
	bridgeSetFilterFlags = 24
	bridgeFilterMember   = 0x00000002
	bridgeFilterOnlyIP   = 0x00000004
	bridgeFilterLegacy   = 0x00000001
)

type darwinController struct{}

type darwinIfDriverRequest struct {
	Name [unix.IFNAMSIZ]byte
	Cmd  uint64
	Len  uint64
	Data uintptr
}

func newController() Controller {
	return darwinController{}
}

func (darwinController) Enable(bridgeName string) (resultErr error) {
	bridgeName = strings.TrimSpace(bridgeName)
	if !validBridgeInterfaceName(bridgeName) {
		return fmt.Errorf("bridge interface name %q is invalid", bridgeName)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("open bridge filter control socket: %w", err)
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close bridge filter control socket: %w", err))
		}
	}()

	var flags uint32
	if err := bridgeFilterIOCTL(fd, bridgeName, bridgeGetFilterFlags, unix.SIOCGDRVSPEC, &flags); err != nil {
		return fmt.Errorf("read bridge filter flags: %w", err)
	}
	if flags&(bridgeFilterLegacy|bridgeFilterOnlyIP) != 0 {
		return fmt.Errorf("bridge filter flags %#x contain unsupported legacy or only-IP state", flags)
	}
	want := flags | bridgeFilterMember
	if err := bridgeFilterIOCTL(fd, bridgeName, bridgeSetFilterFlags, unix.SIOCSDRVSPEC, &want); err != nil {
		return fmt.Errorf("enable PF on bridge members: %w", err)
	}
	var verified uint32
	if err := bridgeFilterIOCTL(fd, bridgeName, bridgeGetFilterFlags, unix.SIOCGDRVSPEC, &verified); err != nil {
		return fmt.Errorf("verify bridge filter flags: %w", err)
	}
	if verified&bridgeFilterMember == 0 {
		return fmt.Errorf("verify bridge filter flags: member filtering is disabled (flags=%#x)", verified)
	}
	return nil
}

func bridgeFilterIOCTL(fd int, bridgeName string, command uint64, request uintptr, flags *uint32) error {
	if flags == nil {
		return fmt.Errorf("bridge filter flags are required")
	}
	var driver darwinIfDriverRequest
	copy(driver.Name[:], bridgeName)
	driver.Cmd = command
	driver.Len = uint64(unsafe.Sizeof(*flags))
	driver.Data = uintptr(unsafe.Pointer(flags))
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(&driver)))
	runtime.KeepAlive(flags)
	runtime.KeepAlive(&driver)
	if errno != 0 {
		return errno
	}
	return nil
}
