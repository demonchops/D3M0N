package main

import (
	"bytes"
	"io"
	"os"
)

// tailer incrementally reads newly-appended, newline-delimited JSON from a
// single file path, by byte offset. It is a pure, read-only file reader:
// it never creates, truncates, locks, or exclusively opens the file, and it
// tolerates the file not existing yet (the run hasn't started) by treating
// that as "nothing new" rather than an error.
//
// It is intentionally the only thing in this program that touches the
// filesystem beyond terminal I/O, and the only file it ever touches is the
// one path it was constructed with.
// maxLineBuf bounds how many unterminated bytes we'll hold while waiting for
// a line's trailing newline. A well-formed event line never approaches this
// (events.py writes one small JSON object per flushed line); if it's ever
// exceeded, treat the buffered bytes as a stuck/corrupt write and drop them
// rather than let them grow without bound.
const maxLineBuf = 1 << 20 // 1 MiB

type tailer struct {
	path   string
	offset int64
	buf    []byte // bytes read past the last complete line, held for next poll
}

func newTailer(path string) *tailer {
	return &tailer{path: path}
}

// poll reads whatever has been appended since the last call and returns the
// newly-complete, successfully-parsed events, in file order. A nil error
// with a nil/empty slice means "nothing new yet" (including "file does not
// exist yet"). Malformed or unrecognized lines are skipped, not surfaced as
// errors, per the event-log contract.
func (t *tailer) poll() ([]Event, error) {
	f, err := os.Open(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()

	if size < t.offset {
		// The file shrank (truncated or replaced by a new run) — restart
		// from the beginning rather than erroring out.
		t.offset = 0
		t.buf = t.buf[:0]
	}
	if size == t.offset {
		return nil, nil
	}

	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return nil, err
	}

	chunk, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	t.offset += int64(len(chunk))
	t.buf = append(t.buf, chunk...)

	var events []Event
	for {
		idx := bytes.IndexByte(t.buf, '\n')
		if idx < 0 {
			break
		}
		line := bytes.TrimRight(t.buf[:idx], "\r")
		t.buf = t.buf[idx+1:]

		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if ev, ok := parseEvent(line); ok {
			events = append(events, ev)
		}
		// malformed/unknown lines: skip silently, never crash the reader.
	}

	if len(t.buf) > maxLineBuf {
		// No newline in sight for an unreasonable amount of data — assume a
		// stuck/corrupt write rather than buffering it forever.
		t.buf = t.buf[:0]
	}

	return events, nil
}
