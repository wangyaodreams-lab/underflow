package auth

import (
	"sync"
	"time"
)

// Limiter is a fixed-window rate limiter keyed by an arbitrary string. It is
// intentionally in-memory: for multi-instance deployments a shared limiter
// should replace it, but it is sufficient for a single process.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   int
	window  time.Duration
	now     func() time.Time
}

type bucket struct {
	count int
	reset time.Time
}

// NewLimiter returns a limiter allowing limit events per window.
func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{
		buckets: make(map[string]*bucket),
		limit:   limit,
		window:  window,
		now:     time.Now,
	}
}

// Allow reports whether an event for key is permitted, consuming a slot if so.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok || now.After(b.reset) {
		l.buckets[key] = &bucket{count: 1, reset: now.Add(l.window)}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}

// RetryAfter returns the time until key's window resets (zero if not limited).
func (l *Limiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return 0
	}
	if d := b.reset.Sub(l.now()); d > 0 {
		return d
	}
	return 0
}

// Cleanup removes expired buckets; call periodically to bound memory.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, b := range l.buckets {
		if now.After(b.reset) {
			delete(l.buckets, k)
		}
	}
}
