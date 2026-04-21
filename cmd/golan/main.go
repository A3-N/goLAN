package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mcrn/goLAN/internal/bridge"
	"github.com/mcrn/goLAN/internal/tui"
)

var version = "dev"

func main() {
	cleanup := flag.Bool("cleanup", false, "Remove any stale bridge interfaces and exit")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("goLAN %s\n", version)
		os.Exit(0)
	}

	// Check for root privileges.
	if os.Geteuid() != 0 {
		fmt.Println()
		fmt.Println("  goLAN requires root privileges to manage network bridges.")
		fmt.Println()
		fmt.Println("  Run with sudo:")
		fmt.Println("    sudo golan")
		fmt.Println()
		os.Exit(1)
	}

	// Handle --cleanup mode.
	if *cleanup {
		fmt.Println("  Cleaning up stale bridge interfaces...")
		cleaned, err := bridge.CleanupStaleBridges()
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			os.Exit(1)
		}
		if len(cleaned) == 0 {
			fmt.Println("  No stale bridges found.")
		} else {
			for _, name := range cleaned {
				fmt.Printf("  ✓ Destroyed %s\n", name)
			}
		}
		os.Exit(0)
	}

	// Launch the TUI.
	p := tea.NewProgram(
		tui.NewModel(),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
