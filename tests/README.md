# Test layout

Go unit tests stay beside the package they test. Many intentionally exercise
unexported parsers, state machines, restoration paths, and bounds; moving them
to a subdirectory would create a different package and force application
internals to become public.

This directory contains tests that are naturally independent of one package:

- `workflow` covers public cross-package product flows.
- `hardware` contains the explicitly gated macOS hardware acceptance harness.

Routine tests must not require root or mutate real network state. The hardware
suite is inert unless its build tag, exact acknowledgement, and explicit cases
are all supplied.
