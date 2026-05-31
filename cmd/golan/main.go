package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"golan/internal/tui"
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

	if _, err := tea.NewProgram(tui.NewModel(), opts...).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "golan: %v\n", err)
		os.Exit(1)
	}
}
