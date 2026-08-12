package bridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// InterfaceRestoreState records every macOS adapter setting changed by
// LockdownInterface. It is safe to persist until shutdown and restore more than
// once.
type InterfaceRestoreState struct {
	IfName              string
	NetworkService      string
	ServiceStateKnown   bool
	ServiceEnabled      bool
	InterfaceStateKnown bool
	InterfaceUp         bool
}

// LockdownInterface snapshots and isolates a physical macOS adapter. It changes
// only the network-service enabled state and administrative interface state so
// RestoreInterfaceState can reverse every successful mutation.
func LockdownInterface(ifName, networkService string) (InterfaceRestoreState, error) {
	return lockdownInterface(context.Background(), execCommandRunner{}, ifName, networkService)
}

func lockdownInterface(ctx context.Context, runner commandRunner, ifName, networkService string) (InterfaceRestoreState, error) {
	state, err := snapshotInterfaceState(ctx, runner, ifName, networkService)
	if err != nil {
		return state, err
	}

	serviceChanged := false
	if state.ServiceEnabled {
		out, err := runner.Run(ctx, 5*time.Second, "networksetup", "-setnetworkserviceenabled", state.NetworkService, "off")
		if err != nil {
			return state, commandError("disable network service", out, err)
		}
		serviceChanged = true
	}

	out, err := runner.Run(ctx, 5*time.Second, "ifconfig", state.IfName, "down")
	if err == nil {
		return state, nil
	}
	lockErr := commandError("bring adapter down", out, err)
	if !serviceChanged {
		return state, lockErr
	}

	rollbackOut, rollbackErr := runner.Run(context.Background(), 5*time.Second, "networksetup", "-setnetworkserviceenabled", state.NetworkService, "on")
	if rollbackErr != nil {
		rollbackErr = commandError("rollback network service", rollbackOut, rollbackErr)
	}
	return state, errors.Join(lockErr, rollbackErr)
}

func snapshotInterfaceState(ctx context.Context, runner commandRunner, ifName, networkService string) (InterfaceRestoreState, error) {
	ifName = strings.TrimSpace(ifName)
	networkService = strings.TrimSpace(networkService)
	state := InterfaceRestoreState{
		IfName:         ifName,
		NetworkService: networkService,
	}
	if ifName == "" {
		return state, fmt.Errorf("adapter name is required")
	}
	if !validInterfaceName(ifName) {
		return state, fmt.Errorf("adapter name %q is invalid", ifName)
	}
	if networkService == "" {
		return state, fmt.Errorf("network service mapping is required for %s", ifName)
	}

	out, err := runner.Run(ctx, 5*time.Second, "networksetup", "-getnetworkserviceenabled", networkService)
	if err != nil {
		return state, commandError("read service state", out, err)
	}
	switch strings.ToLower(strings.TrimSpace(out)) {
	case "enabled":
		state.ServiceStateKnown = true
		state.ServiceEnabled = true
	case "disabled":
		state.ServiceStateKnown = true
	default:
		return state, fmt.Errorf("read service state for %s: unexpected output %q", networkService, strings.TrimSpace(out))
	}

	out, err = runner.Run(ctx, 5*time.Second, "ifconfig", ifName)
	if err != nil {
		return state, commandError("read adapter state", out, err)
	}
	state.InterfaceUp = interfaceAdminUp(out)
	state.InterfaceStateKnown = true
	return state, nil
}

// RestoreInterfaceState restores host-side settings captured before lockdown.
// Service state is restored before the final administrative state so an
// enabled service cannot override an originally-down interface.
func RestoreInterfaceState(state InterfaceRestoreState) error {
	return restoreInterfaceState(context.Background(), execCommandRunner{}, state)
}

// SetInterfaceState changes one validated adapter's administrative state.
func SetInterfaceState(ifName, state string) error {
	return setInterfaceState(context.Background(), execCommandRunner{}, ifName, state)
}

func setInterfaceState(ctx context.Context, runner commandRunner, ifName, state string) error {
	ifName = strings.TrimSpace(ifName)
	state = strings.ToLower(strings.TrimSpace(state))
	if ifName == "" {
		return fmt.Errorf("adapter name is required")
	}
	if !validInterfaceName(ifName) {
		return fmt.Errorf("adapter name %q is invalid", ifName)
	}
	if state != "up" && state != "down" {
		return fmt.Errorf("adapter state must be up or down")
	}
	out, err := runner.Run(ctx, 5*time.Second, "ifconfig", ifName, state)
	if err != nil {
		return commandError("set adapter state", out, err)
	}
	return nil
}

func restoreInterfaceState(ctx context.Context, runner commandRunner, state InterfaceRestoreState) error {
	ifName := strings.TrimSpace(state.IfName)
	if ifName == "" {
		return nil
	}
	if !validInterfaceName(ifName) {
		return fmt.Errorf("adapter name %q is invalid", ifName)
	}
	var errs []error
	if state.ServiceStateKnown && state.NetworkService != "" {
		desired := "off"
		if state.ServiceEnabled {
			desired = "on"
		}
		out, err := runner.Run(ctx, 5*time.Second, "networksetup", "-setnetworkserviceenabled", state.NetworkService, desired)
		if err != nil {
			errs = append(errs, commandError("restore network service", out, err))
		}
	}
	if state.InterfaceStateKnown {
		desiredState := "down"
		if state.InterfaceUp {
			desiredState = "up"
		}
		if out, err := runner.Run(ctx, 5*time.Second, "ifconfig", ifName, desiredState); err != nil {
			errs = append(errs, commandError("restore adapter state", out, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("restore %s: %w", ifName, err)
	}
	return nil
}

func interfaceAdminUp(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		start := strings.Index(line, "<")
		end := strings.Index(line, ">")
		if start < 0 || end <= start {
			continue
		}
		for _, flag := range strings.Split(line[start+1:end], ",") {
			if strings.TrimSpace(flag) == "UP" {
				return true
			}
		}
		return false
	}
	return false
}

func validInterfaceName(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for i, char := range name {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') {
			continue
		}
		if i > 0 && (char == '-' || char == '_' || char == '.' || char == ':') {
			continue
		}
		return false
	}
	return true
}

func validBridgeInterfaceName(name string) bool {
	if !validInterfaceName(name) || !strings.HasPrefix(name, "bridge") {
		return false
	}
	suffix := strings.TrimPrefix(name, "bridge")
	if suffix == "" {
		return false
	}
	for _, char := range suffix {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func commandError(operation, output string, err error) error {
	output = strings.TrimSpace(output)
	if output == "" {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s: %w (%s)", operation, err, output)
}
