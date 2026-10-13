package main

import "github.com/charmbracelet/lipgloss"

// Color palette. Kept small and terminal-friendly (works on 256-color and
// true-color terminals alike via lipgloss's adaptive color handling).
var (
	colorAccent  = lipgloss.Color("69")  // blue — headers, borders
	colorMuted   = lipgloss.Color("244") // grey — secondary text
	colorOK      = lipgloss.Color("42")  // green — success
	colorFail    = lipgloss.Color("203") // red — failure
	colorPending = lipgloss.Color("214") // amber — in flight
	colorWhite   = lipgloss.Color("255")
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(colorAccent).
			Padding(0, 1)

	sectionHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorAccent)

	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorMuted)

	valueStyle = lipgloss.NewStyle().
			Foreground(colorWhite)

	mutedStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	okBadgeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorOK)

	failBadgeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorFail)

	pendingBadgeStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorPending)

	completeBannerStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorWhite).
				Background(colorOK).
				Padding(0, 1)

	helpStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			Italic(true)
)
