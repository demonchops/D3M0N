package main

import "encoding/json"

// EventType is the discriminant of the fixed JSONL event contract produced
// by the Python agent (src/d3m0n/agent/events.py). This set must stay in
// sync with that file; it is intentionally small and closed.
type EventType string

const (
	EventRunStart EventType = "run_start"
	EventStep     EventType = "step"
	EventToolDone EventType = "tool_done"
	EventRunDone  EventType = "run_done"
)

// ToolRef names a tool invocation planned for a step, as embedded in a
// "step" event's "tools" array.
type ToolRef struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

// Event is the parsed, typed form of one JSONL line. Only the fields that
// apply to ev.Type are meaningful; the rest are zero values.
type Event struct {
	Type EventType
	TS   float64

	// run_start
	Objective string
	Scope     string
	MaxSteps  int

	// step
	Step  int
	Tools []ToolRef

	// tool_done (Step also applies here)
	Tool   string
	Target string
	OK     bool
	Note   string

	// run_done
	Summary       string
	FindingsCount int
	StepsUsed     int
}

// rawEvent mirrors the on-disk JSON shape for all four event types at once.
// Unmarshaling into one struct is simplest and safest: a field that doesn't
// apply to a given "type" is just left at its zero value, and any JSON
// fields we don't know about are silently ignored by encoding/json, so the
// reader tolerates future additive changes to the schema.
type rawEvent struct {
	Type          string    `json:"type"`
	TS            float64   `json:"ts"`
	Objective     string    `json:"objective"`
	Scope         string    `json:"scope"`
	MaxSteps      int       `json:"max_steps"`
	Step          int       `json:"step"`
	Tools         []ToolRef `json:"tools"`
	Tool          string    `json:"tool"`
	Target        string    `json:"target"`
	OK            bool      `json:"ok"`
	Note          string    `json:"note"`
	Summary       string    `json:"summary"`
	FindingsCount int       `json:"findings_count"`
	StepsUsed     int       `json:"steps_used"`
}

// parseEvent decodes one JSONL line. It returns ok=false for malformed JSON
// or an unrecognized "type" — callers must skip those lines rather than
// treat them as an error; the log is a best-effort side channel and a
// partially-written or forward-incompatible line must never crash the
// viewer.
func parseEvent(line []byte) (Event, bool) {
	var raw rawEvent
	if err := json.Unmarshal(line, &raw); err != nil {
		return Event{}, false
	}

	switch EventType(raw.Type) {
	case EventRunStart, EventStep, EventToolDone, EventRunDone:
		// recognized
	default:
		return Event{}, false
	}

	return Event{
		Type:          EventType(raw.Type),
		TS:            raw.TS,
		Objective:     raw.Objective,
		Scope:         raw.Scope,
		MaxSteps:      raw.MaxSteps,
		Step:          raw.Step,
		Tools:         raw.Tools,
		Tool:          raw.Tool,
		Target:        raw.Target,
		OK:            raw.OK,
		Note:          raw.Note,
		Summary:       raw.Summary,
		FindingsCount: raw.FindingsCount,
		StepsUsed:     raw.StepsUsed,
	}, true
}
