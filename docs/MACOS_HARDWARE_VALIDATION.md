# macOS hardware validation

The privileged suite lives in `tests/hardware` so application packages never
contain a test-only network mutation harness. Routine `go test ./...` only runs
its contract tests and never enables hardware cases.

Run the tagged suite only in an isolated, authorized wired lab. It requires
macOS, root, an exact acknowledgement, and an explicit comma-separated case
list:

```bash
sudo env \
  GOLAN_HARDWARE_ACK=I_UNDERSTAND_GOLAN_WILL_MUTATE_NETWORK_STATE \
  GOLAN_HARDWARE_CASES=pf-syntax \
  go test -tags=golan_privileged -run '^TestPrivilegedMacOSHardware$' \
  -count=1 ./tests/hardware
```

Available cases are `pf-syntax`, `fast`, `fast-discovery`, `controlled`,
`takeover`, `edge-route`, and `edge-port-forward`. Live inline cases require
`GOLAN_HARDWARE_HOST` and `GOLAN_HARDWARE_SWITCH`; Edge cases require
`GOLAN_HARDWARE_DOWNSTREAM`. Fast and Takeover also require
`GOLAN_HARDWARE_TARGET_MAC`. The contract rejects ambiguous adapters, unsafe
defaults, invalid bounds, and missing per-case settings before mutation.

Use `GOLAN_HARDWARE_DURATION`, `GOLAN_HARDWARE_ACTIVE_TIMEOUT`, and
`GOLAN_HARDWARE_MIN_PACKETS` to tune bounded observation. Optional expectations
include `GOLAN_HARDWARE_EXPECT_EAPOL` and `GOLAN_HARDWARE_EXPECT_VLAN`. Review
`tests/hardware/contract.go` for the complete environment contract before any
live run.
