package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// idleTTL is how long an unused per-key bucket is kept before the janitor evicts
// it, bounding memory under a churn of distinct keys (many client IPs).
const idleTTL = 10 * time.Minute

// Memory is an in-process Limiter backed by per-key token buckets. It is correct
// for a single instance (the fs / single-box shape). Horizontal deployments
// behind a load balancer need the Redis limiter so counters are shared.
type Memory struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	stop    chan struct{}
}

type bucket struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// NewMemory returns an in-memory limiter and starts its eviction janitor. Call
// Close to stop it.
func NewMemory() *Memory {
	m := &Memory{buckets: make(map[string]*bucket), stop: make(chan struct{})}
	go m.janitor()
	return m
}

// Allow reports whether one more event for key is permitted under limit events
// per window. The bucket bursts up to limit, then refills at limit/window.
func (m *Memory) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 || window <= 0 {
		return true, nil // unconfigured rate: no limit
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	b, ok := m.buckets[key]
	if !ok {
		b = &bucket{lim: rate.NewLimiter(rate.Every(window/time.Duration(limit)), limit)}
		m.buckets[key] = b
	}
	b.lastSeen = time.Now()
	return b.lim.Allow(), nil
}

// Close stops the janitor goroutine.
func (m *Memory) Close() { close(m.stop) }

func (m *Memory) janitor() {
	t := time.NewTicker(idleTTL)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case now := <-t.C:
			m.mu.Lock()
			for k, b := range m.buckets {
				if now.Sub(b.lastSeen) > idleTTL {
					delete(m.buckets, k)
				}
			}
			m.mu.Unlock()
		}
	}
}
