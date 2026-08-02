package bridgefilter

import "strings"

// Controller enables PF member filtering for a kernel bridge.
type Controller interface {
	Enable(bridgeName string) error
}

// New returns the platform bridge-filter controller.
func New() Controller {
	return newController()
}

func validBridgeInterfaceName(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) < len("bridge0") || len(name) > 15 || !strings.HasPrefix(name, "bridge") {
		return false
	}
	for _, char := range strings.TrimPrefix(name, "bridge") {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
