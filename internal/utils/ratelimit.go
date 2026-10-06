package utils

import (
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter. The zero value is not usable; use
// NewLimiter. It is safe for concurrent use.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

// NewLimiter allows `rate` events per second with bursts of up to `burst`.
func NewLimiter(rate float64, burst int) *Limiter {
	return newLimiter(rate, burst, time.Now)
}

func newLimiter(rate float64, burst int, now func() time.Time) *Limiter {
	return &Limiter{rate: rate, burst: float64(burst), tokens: float64(burst), last: now(), now: now}
}

// Allow reports whether one event may happen now, consuming a token if so.
func (l *Limiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.last = now

	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// KeyedLimiter keeps one Limiter per key (for example a source IP) and
// forgets idle keys so the map cannot grow without bound.
type KeyedLimiter struct {
	mu       sync.Mutex
	rate     float64
	burst    int
	maxKeys  int
	limiters map[string]*keyedEntry
	now      func() time.Time
}

type keyedEntry struct {
	l    *Limiter
	seen time.Time
}

// NewKeyedLimiter creates per-key limiters; at most maxKeys keys are tracked.
func NewKeyedLimiter(rate float64, burst, maxKeys int) *KeyedLimiter {
	return &KeyedLimiter{
		rate: rate, burst: burst, maxKeys: maxKeys,
		limiters: make(map[string]*keyedEntry),
		now:      time.Now,
	}
}

// Allow reports whether an event for key may happen now.
func (k *KeyedLimiter) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()

	now := k.now()
	e, ok := k.limiters[key]
	if !ok {
		if len(k.limiters) >= k.maxKeys {
			k.evictLocked(now)
			if len(k.limiters) >= k.maxKeys {
				return false // under key-flooding, refuse unknown sources
			}
		}
		e = &keyedEntry{l: newLimiter(k.rate, k.burst, k.now)}
		k.limiters[key] = e
	}
	e.seen = now
	return e.l.Allow()
}

// evictLocked drops keys idle for over a minute.
func (k *KeyedLimiter) evictLocked(now time.Time) {
	for key, e := range k.limiters {
		if now.Sub(e.seen) > time.Minute {
			delete(k.limiters, key)
		}
	}
}
