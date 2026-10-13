// Command d3m0n-tui is a small, read-only terminal dashboard that live-tails
// a D3M0N agent run's JSONL event log and renders its progress.
//
// It is a pure viewer by design: it opens exactly one file (the path given
// on the command line) for reading, polls it by seeking from the last-read
// byte offset, and renders a terminal UI. It never opens a network
// connection and never execs a subprocess — see tail.go and events.go for
// the only file I/O in this program, and model.go for everything else.
package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <path-to-events.jsonl>\n", os.Args[0])
		os.Exit(2)
	}

	path := os.Args[1]

	p := tea.NewProgram(newModel(path), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "d3m0n-tui: %v\n", err)
		os.Exit(1)
	}
}
