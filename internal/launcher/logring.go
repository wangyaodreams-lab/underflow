package launcher

import "sync"

// logLine is a single captured output line from the server process.
type logLine struct {
	Seq  uint64 `json:"seq"`
	Text string `json:"text"`
}

// logRing is a bounded, sequence-numbered buffer of server output that
// supports fan-out to live subscribers. Every line gets a monotonically
// increasing sequence number so an SSE client that reconnects with
// Last-Event-ID can replay exactly what it missed.
type logRing struct {
	mu   sync.Mutex
	max  int
	seq  uint64
	buf  []logLine
	subs map[chan logLine]struct{}
}

func newLogRing(max int) *logRing {
	if max <= 0 {
		max = 2000
	}
	return &logRing{max: max, subs: make(map[chan logLine]struct{})}
}

// add appends a line and notifies subscribers. Subscribers that cannot keep up
// are skipped rather than allowed to block the server's output pipe.
func (r *logRing) add(text string) {
	r.mu.Lock()
	r.seq++
	line := logLine{Seq: r.seq, Text: text}
	r.buf = append(r.buf, line)
	if len(r.buf) > r.max {
		r.buf = append(r.buf[:0], r.buf[len(r.buf)-r.max:]...)
	}
	for ch := range r.subs {
		select {
		case ch <- line:
		default:
		}
	}
	r.mu.Unlock()
}

// since returns the buffered lines with Seq > after.
func (r *logRing) since(after uint64) []logLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]logLine, 0, len(r.buf))
	for _, l := range r.buf {
		if l.Seq > after {
			out = append(out, l)
		}
	}
	return out
}

// subscribe registers a live feed. The returned channel is closed by detach.
func (r *logRing) subscribe() (uint64, chan logLine) {
	ch := make(chan logLine, 512)
	r.mu.Lock()
	head := r.seq
	r.subs[ch] = struct{}{}
	r.mu.Unlock()
	return head, ch
}

func (r *logRing) detach(ch chan logLine) {
	r.mu.Lock()
	if _, ok := r.subs[ch]; ok {
		delete(r.subs, ch)
		close(ch)
	}
	r.mu.Unlock()
}

func (r *logRing) clear() {
	r.mu.Lock()
	r.buf = nil
	r.mu.Unlock()
}
