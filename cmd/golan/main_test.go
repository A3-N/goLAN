package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunPrintsVersionWithoutStartingWorkbench(t *testing.T) {
	previous := version
	version = "test-version"
	t.Cleanup(func() { version = previous })

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, "linux", 1000, &stdout, &stderr); code != 0 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	if stdout.String() != "golan test-version\n" || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunRejectsUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"not-a-command"}, "linux", 1000, &stdout, &stderr); code != 2 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "golan [new <name>|open <project>]") || stdout.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
