// Package pfutil provides shared, narrowly scoped helpers for goLAN's owned
// macOS PF anchors.
package pfutil

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golan/internal/policy"
	"golan/internal/syncgate"
)

// AnchorOperations names one owned PF child anchor and its lifecycle actions.
type AnchorOperations struct {
	Anchor            string
	FlushKind         string
	Timeout           time.Duration
	ValidateOperation string
	LoadOperation     string
	FlushOperation    string
	RulesError        string
	RunnerError       string
}

// AnchorState is a payload-free ownership snapshot. Restoration tokens never
// leave Backend.
type AnchorState struct {
	Anchor           string
	Loaded           bool
	EnableTokenOwned bool
}

// Backend serializes one owned PF child anchor and its restoration token.
type Backend struct {
	mu         sync.Mutex
	gate       syncgate.Gate
	runner     Runner
	operations AnchorOperations
	loaded     bool
	token      string
}

// NewBackend creates one isolated anchor backend with the supplied runner.
func NewBackend(operations AnchorOperations, runner Runner) *Backend {
	return &Backend{operations: operations, runner: runner}
}

// State returns a payload-free ownership snapshot.
func (backend *Backend) State() AnchorState {
	if backend == nil {
		return AnchorState{}
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return AnchorState{
		Anchor: backend.operations.Anchor, Loaded: backend.loaded,
		EnableTokenOwned: backend.token != "",
	}
}

// Apply validates and replaces the configured child anchor.
func (backend *Backend) Apply(ctx context.Context, rules string) error {
	if strings.TrimSpace(rules) == "" {
		return fmt.Errorf("%s", backend.operations.RulesError)
	}
	release := backend.gate.Enter()
	defer release()
	backend.mu.Lock()
	runner := backend.runner
	tokenOwned := backend.token != ""
	backend.mu.Unlock()
	if runner == nil {
		return fmt.Errorf("%s", backend.operations.RunnerError)
	}
	return LoadAnchor(ctx, runner, backend.operations, rules, tokenOwned,
		func(token string) {
			backend.mu.Lock()
			backend.token = token
			backend.mu.Unlock()
		},
		func() {
			backend.mu.Lock()
			backend.loaded = true
			backend.mu.Unlock()
		},
	)
}

// Restore flushes the configured anchor and releases only Backend's token.
func (backend *Backend) Restore(ctx context.Context) error {
	if backend == nil {
		return nil
	}
	release := backend.gate.Enter()
	defer release()
	backend.mu.Lock()
	runner := backend.runner
	loaded := backend.loaded
	token := backend.token
	backend.mu.Unlock()
	if runner == nil {
		return fmt.Errorf("%s", backend.operations.RunnerError)
	}
	return RestoreAnchor(ctx, runner, backend.operations, loaded, token,
		func() {
			backend.mu.Lock()
			backend.loaded = false
			backend.mu.Unlock()
		},
		func() {
			backend.mu.Lock()
			backend.token = ""
			backend.mu.Unlock()
		},
	)
}

// Runner executes pfctl with explicit arguments and optional standard input.
type Runner interface {
	Run(context.Context, string, []string, string) (string, error)
}

// ExecRunner invokes the system pfctl process.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, name string, args []string, input string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	return string(output), err
}

// List renders one deterministic PF scalar or brace-delimited list.
func List(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return "{ " + strings.Join(values, ", ") + " }"
}

// Ports renders a policy port set in PF syntax.
func Ports(set policy.PortSet) string {
	var items []string
	for _, value := range set.Values {
		items = append(items, strconv.Itoa(int(value)))
	}
	for _, value := range set.Ranges {
		items = append(items, fmt.Sprintf("%d:%d", value.First, value.Last))
	}
	if len(items) == 0 {
		return ""
	}
	result := List(items)
	if set.Negate {
		return "!= " + result
	}
	return result
}

// EnsureEnabled reads PF state and acquires a restoration token only when PF
// is disabled and the caller does not already own one.
func EnsureEnabled(ctx context.Context, runner Runner, timeout time.Duration, tokenOwned bool) (string, error) {
	infoCtx, cancelInfo := context.WithTimeout(ctx, timeout)
	info, err := runner.Run(infoCtx, "pfctl", []string{"-s", "info"}, "")
	cancelInfo()
	if err != nil {
		return "", CommandError("read PF state", info, err)
	}
	if strings.Contains(strings.ToLower(info), "status: enabled") || tokenOwned {
		return "", nil
	}
	enableCtx, cancelEnable := context.WithTimeout(ctx, timeout)
	output, err := runner.Run(enableCtx, "pfctl", []string{"-E"}, "")
	cancelEnable()
	if err != nil {
		return "", CommandError("enable PF", output, err)
	}
	token := parseToken(output)
	if token == "" {
		return "", fmt.Errorf("enable PF did not return a restoration token")
	}
	return token, nil
}

// LoadAnchor validates a complete ruleset, enables PF if needed, marks cleanup
// pending, and replaces only the configured child anchor.
func LoadAnchor(
	ctx context.Context,
	runner Runner,
	operations AnchorOperations,
	rules string,
	tokenOwned bool,
	storeToken func(string),
	markOwned func(),
) error {
	validateCtx, cancelValidate := context.WithTimeout(ctx, operations.Timeout)
	output, err := runner.Run(validateCtx, "pfctl", []string{"-vnf", "-"}, rules)
	cancelValidate()
	if err != nil {
		return CommandError(operations.ValidateOperation, output, err)
	}
	token, err := EnsureEnabled(ctx, runner, operations.Timeout, tokenOwned)
	if err != nil {
		return err
	}
	if token != "" {
		storeToken(token)
	}
	// A failed load may still have changed the owned anchor, so restoration is
	// pending before pfctl is allowed to touch it.
	markOwned()
	loadCtx, cancelLoad := context.WithTimeout(ctx, operations.Timeout)
	output, err = runner.Run(loadCtx, "pfctl", []string{"-a", operations.Anchor, "-f", "-"}, rules)
	cancelLoad()
	if err != nil {
		return CommandError(operations.LoadOperation, output, err)
	}
	return nil
}

// RestoreAnchor flushes only an owned child anchor, then releases only the PF
// enable token acquired by its caller. Failed steps remain retryable.
func RestoreAnchor(
	ctx context.Context,
	runner Runner,
	operations AnchorOperations,
	owned bool,
	token string,
	clearOwned func(),
	clearToken func(),
) error {
	var errs []error
	if owned {
		flushCtx, cancelFlush := context.WithTimeout(ctx, operations.Timeout)
		output, err := runner.Run(flushCtx, "pfctl", []string{"-a", operations.Anchor, "-F", operations.FlushKind}, "")
		cancelFlush()
		if err != nil {
			errs = append(errs, CommandError(operations.FlushOperation, output, err))
		} else {
			clearOwned()
			owned = false
		}
	}
	if !owned && token != "" {
		tokenCtx, cancelToken := context.WithTimeout(ctx, operations.Timeout)
		output, err := runner.Run(tokenCtx, "pfctl", []string{"-X", token}, "")
		cancelToken()
		if err != nil {
			errs = append(errs, CommandError("release PF token", output, err))
		} else {
			clearToken()
		}
	}
	return errors.Join(errs...)
}

// CommandError adds bounded command output to an operation error.
func CommandError(operation, output string, err error) error {
	output = strings.TrimSpace(output)
	if output == "" {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s: %w (%s)", operation, err, output)
}

func parseToken(output string) string {
	fields := strings.Fields(output)
	for index, field := range fields {
		if !strings.EqualFold(strings.Trim(field, ":"), "token") {
			continue
		}
		for next := index + 1; next < len(fields); next++ {
			candidate := strings.Trim(fields[next], ":.,;()[]")
			if candidate != "" {
				return candidate
			}
		}
	}
	return ""
}
