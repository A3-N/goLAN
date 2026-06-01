package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"golan/internal/tui"
	"golang.org/x/sys/unix"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "Show version and exit")
	noAlt := flag.Bool("no-alt", false, "Run without the alternate terminal screen")
	flag.Parse()

	if *showVersion {
		fmt.Printf("golan %s\n", version)
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "golan requires root privileges to inspect adapters and capture traffic; run it with sudo")
		os.Exit(1)
	}

	opts := []tea.ProgramOption{}
	if !*noAlt {
		opts = append(opts, tea.WithAltScreen())
	}

	width, height := terminalSize()
	finalModel, err := tea.NewProgram(tui.NewModelWithSize(width, height), opts...).Run()
	cleanupErr := tui.Shutdown(finalModel)
	if errors.Is(err, tea.ErrInterrupted) {
		err = nil
	}
	if err != nil || cleanupErr != nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "golan: %v\n", err)
		}
		if cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "golan cleanup: %v\n", cleanupErr)
		}
		os.Exit(1)
	}
}

func terminalSize() (int, int) {
	size, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil || size == nil {
		return 0, 0
	}
	return int(size.Col), int(size.Row)
}
