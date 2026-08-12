package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	workproject "golan/internal/project"
	"golan/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/sys/unix"
)

var version = "dev"

func main() {
	if code := run(os.Args[1:], runtime.GOOS, os.Geteuid(), os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}

func run(args []string, goos string, effectiveUID int, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("golan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "Show version and exit")
	noAlt := flags.Bool("no-alt", false, "Run without the alternate terminal screen")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "golan %s\n", version)
		return 0
	}
	remaining := flags.Args()

	offline := goos != "darwin" || effectiveUID != 0
	var project *workproject.Project
	rememberProject := false
	if len(remaining) > 0 {
		switch strings.ToLower(remaining[0]) {
		case "new":
			if len(remaining) != 2 {
				fmt.Fprintln(stderr, "golan: use: golan new <name>")
				return 2
			}
			var err error
			project, err = workproject.NewDefault(remaining[1])
			if err != nil {
				fmt.Fprintln(stderr, "golan new:", err)
				return 1
			}
		case "open":
			if len(remaining) != 2 {
				fmt.Fprintln(stderr, "golan: use: golan open <project.golan|project.golanproj>")
				return 2
			}
			var err error
			project, err = openProjectArgument(remaining[1])
			if err != nil {
				fmt.Fprintln(stderr, "golan open:", err)
				return 1
			}
			rememberProject = true
		default:
			fmt.Fprintln(stderr, "golan: use: golan [new <name>|open <project>]")
			return 2
		}
	}
	if project != nil && rememberProject {
		if err := workproject.RememberRecentProject(project); err != nil {
			fmt.Fprintln(stderr, "golan warning: remember recent project:", err)
		}
	}

	opts := []tea.ProgramOption{tea.WithMouseAllMotion()}
	if !*noAlt {
		opts = append(opts, tea.WithAltScreen())
	}

	width, height := terminalSize()
	model := tui.NewStartupModelWithSize(width, height, offline)
	if project != nil {
		model = tui.NewProjectModel(project, offline, width, height)
	}
	finalModel, err := tea.NewProgram(model, opts...).Run()
	cleanupErr := tui.Shutdown(finalModel)
	for _, dir := range tui.PcapDirs(finalModel) {
		fmt.Fprintf(stdout, "pcaps: %s\n", dir)
	}
	if errors.Is(err, tea.ErrInterrupted) {
		err = nil
	}
	if err != nil || cleanupErr != nil {
		if err != nil {
			fmt.Fprintf(stderr, "golan: %v\n", err)
		}
		if cleanupErr != nil {
			fmt.Fprintf(stderr, "golan cleanup: %v\n", cleanupErr)
		}
		return 1
	}
	return 0
}

func openProjectArgument(path string) (*workproject.Project, error) {
	if !strings.EqualFold(filepath.Ext(path), ".golanproj") {
		return workproject.Open(path)
	}
	root, err := workproject.DefaultRoot()
	if err != nil {
		return nil, err
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return workproject.ImportBundle(context.Background(), path, root, name)
}

func terminalSize() (int, int) {
	size, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil || size == nil {
		return 0, 0
	}
	return int(size.Col), int(size.Row)
}
