package main

import (
	"fmt"
	"math"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// pollInterval is how often we re-check the event file for new bytes. The
// task calls for ~300ms, polling by seeking from the last-read offset
// rather than any OS-specific file-watch mechanism.
const pollInterval = 300 * time.Millisecond

// maxRecent bounds the "recent completed calls" list so the dashboard
// stays O(1) in memory regardless of how long a run goes on for.
const maxRecent = 12

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// tickMsg drives the poll loop.
type tickMsg struct{}

func tickCmd() tea.Cmd {
	return tea.Tick(pollInterval, func(time.Time) tea.Msg { return tickMsg{} })
}

// completedCall is one finished tool_done event, as shown in the recent list.
type completedCall struct {
	Step   int
	Tool   string
	Target string
	OK     bool
	Note   string
}

// pendingTool is one tool from a "step" event that we're still waiting on a
// matching tool_done for.
type pendingTool struct {
	Name   string
	Target string
}

// model is the single bubbletea Model for the whole dashboard. It only
// ever changes in response to messages from its own tick loop (file polls)
// or terminal input/resize — it has no other source of state.
type model struct {
	t *tailer

	// Set once run_start is seen.
	haveStart bool
	objective string
	scope     string
	maxSteps  int
	startedAt time.Time // wall-clock time derived from run_start's ts field

	// Current-step tracking, from the most recent "step" event.
	haveStep    bool
	currentStep int
	pending     []pendingTool

	recent        []completedCall // most-recent-first, capped at maxRecent
	findingsCount int             // count of tool_done events where ok == true

	// Set once run_done is seen; once true, polling stops.
	done          bool
	summary       string
	finalFindings int
	stepsUsed     int

	readErr error // last non-fatal poll error, surfaced but never fatal

	spinnerIdx int
	width      int
	height     int
}

func newModel(path string) model {
	return model{t: newTailer(path)}
}

func (m model) Init() tea.Cmd {
	return tickCmd()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		}
		return m, nil

	case tickMsg:
		events, err := m.t.poll()
		m.readErr = err
		for _, ev := range events {
			m.applyEvent(ev)
		}
		m.spinnerIdx++

		if m.done {
			// run_done seen: stop polling and leave "live" mode for good,
			// rather than continuing to tail forever.
			return m, nil
		}
		return m, tickCmd()
	}

	return m, nil
}

// applyEvent folds one parsed event into the model's state. Events of a
// type we don't recognize never reach here (tail.go/events.go already
// filter those out).
func (m *model) applyEvent(ev Event) {
	switch ev.Type {

	case EventRunStart:
		m.haveStart = true
		m.objective = ev.Objective
		m.scope = ev.Scope
		m.maxSteps = ev.MaxSteps
		m.startedAt = tsToTime(ev.TS)

	case EventStep:
		m.haveStep = true
		m.currentStep = ev.Step
		m.pending = make([]pendingTool, 0, len(ev.Tools))
		for _, tr := range ev.Tools {
			m.pending = append(m.pending, pendingTool{Name: tr.Name, Target: tr.Target})
		}

	case EventToolDone:
		if ev.OK {
			m.findingsCount++
		}

		// Clear the matching in-flight tool, only if this tool_done belongs
		// to the step we're currently tracking.
		if m.haveStep && ev.Step == m.currentStep {
			for i, p := range m.pending {
				if p.Name == ev.Tool && p.Target == ev.Target {
					m.pending = append(m.pending[:i], m.pending[i+1:]...)
					break
				}
			}
		}

		call := completedCall{
			Step:   ev.Step,
			Tool:   ev.Tool,
			Target: ev.Target,
			OK:     ev.OK,
			Note:   ev.Note,
		}
		m.recent = append([]completedCall{call}, m.recent...)
		if len(m.recent) > maxRecent {
			m.recent = m.recent[:maxRecent]
		}

	case EventRunDone:
		m.done = true
		m.summary = ev.Summary
		m.finalFindings = ev.FindingsCount
		m.stepsUsed = ev.StepsUsed
	}
}

// tsToTime converts a Unix-epoch-seconds float (the event log's "ts" field)
// into a time.Time.
func tsToTime(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64(math.Round((ts - float64(sec)) * 1e9))
	return time.Unix(sec, nsec)
}

func (m model) View() string {
	var b strings.Builder

	title := "D3M0N live run"
	if m.done {
		title = "D3M0N run — complete"
	}
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")

	if !m.haveStart {
		b.WriteString(mutedStyle.Render(fmt.Sprintf("waiting for %s ...", m.t.path)))
		if m.readErr != nil {
			b.WriteString("\n")
			b.WriteString(failBadgeStyle.Render(fmt.Sprintf("read error: %v", m.readErr)))
		}
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render("q to quit"))
		return b.String()
	}

	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")

	if m.done {
		b.WriteString(m.renderCompleted())
	} else {
		b.WriteString(m.renderInFlight())
		b.WriteString("\n\n")
	}

	b.WriteString(sectionHeaderStyle.Render("Recent tool calls"))
	b.WriteString("\n")
	b.WriteString(m.renderRecent())
	b.WriteString("\n")

	b.WriteString(m.renderFooter())

	return b.String()
}

func (m model) renderHeader() string {
	var b strings.Builder

	b.WriteString(labelStyle.Render("Objective: "))
	b.WriteString(valueStyle.Render(m.objective))
	b.WriteString("\n")

	b.WriteString(labelStyle.Render("Scope:     "))
	b.WriteString(valueStyle.Render(m.scope))
	b.WriteString("\n\n")

	step := m.currentStep
	if m.done {
		step = m.stepsUsed
	}
	b.WriteString(labelStyle.Render("Progress:  "))
	b.WriteString(valueStyle.Render(fmt.Sprintf("step %d / %d", step, m.maxSteps)))
	b.WriteString("  ")
	b.WriteString(renderProgressBar(step, m.maxSteps, 30))
	b.WriteString("\n")

	elapsed := time.Since(m.startedAt)
	b.WriteString(labelStyle.Render("Elapsed:   "))
	b.WriteString(valueStyle.Render(formatDuration(elapsed)))
	b.WriteString("\n")

	b.WriteString(labelStyle.Render("Findings:  "))
	count := m.findingsCount
	if m.done {
		count = m.finalFindings
	}
	b.WriteString(okBadgeStyle.Render(fmt.Sprintf("%d", count)))

	return b.String()
}

func (m model) renderInFlight() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("In flight"))
	b.WriteString("\n")

	if !m.haveStep || len(m.pending) == 0 {
		b.WriteString(mutedStyle.Render("  (none)"))
		return b.String()
	}

	spin := spinnerFrames[m.spinnerIdx%len(spinnerFrames)]
	for _, p := range m.pending {
		b.WriteString("  ")
		b.WriteString(pendingBadgeStyle.Render(spin))
		b.WriteString(" ")
		b.WriteString(valueStyle.Render(p.Name))
		if p.Target != "" {
			b.WriteString(mutedStyle.Render(" -> " + p.Target))
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func (m model) renderRecent() string {
	if len(m.recent) == 0 {
		return mutedStyle.Render("  (none yet)")
	}

	var b strings.Builder
	for _, c := range m.recent {
		badge := okBadgeStyle.Render("OK  ")
		if !c.OK {
			badge = failBadgeStyle.Render("FAIL")
		}
		line := fmt.Sprintf("  [%s] step %d  %s", badge, c.Step, c.Tool)
		b.WriteString(line)
		if c.Target != "" {
			b.WriteString(mutedStyle.Render(" -> " + c.Target))
		}
		if c.Note != "" {
			b.WriteString(mutedStyle.Render("  (" + c.Note + ")"))
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func (m model) renderCompleted() string {
	var b strings.Builder
	b.WriteString(completeBannerStyle.Render("RUN COMPLETE"))
	b.WriteString("\n\n")
	b.WriteString(labelStyle.Render("Summary:    "))
	b.WriteString(valueStyle.Render(m.summary))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Steps used: "))
	b.WriteString(valueStyle.Render(fmt.Sprintf("%d / %d", m.stepsUsed, m.maxSteps)))
	b.WriteString("\n\n")
	return b.String()
}

func (m model) renderFooter() string {
	status := helpStyle.Render("q to quit")
	if m.readErr != nil {
		status = failBadgeStyle.Render(fmt.Sprintf("read error: %v", m.readErr)) + "  " + status
	}
	return status
}

// renderProgressBar draws a simple [####......] N% style bar without
// pulling in an extra bubbles component.
func renderProgressBar(current, total, width int) string {
	if total <= 0 {
		return lipgloss.NewStyle().Foreground(colorMuted).Render(strings.Repeat("░", width))
	}
	frac := float64(current) / float64(total)
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	filled := int(math.Round(frac * float64(width)))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return lipgloss.NewStyle().Foreground(colorAccent).Render(bar)
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}
