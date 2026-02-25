// Package ratelimit provides a per-IP token-bucket rate limiter.
package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type bucket struct {
	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time
}

// Limiter is a per-IP token-bucket rate limiter.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens (requests) per second
}

// New creates a Limiter that allows rate requests per second per IP.
func New(rate float64) *Limiter {
	l := &Limiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
	}
	go l.cleanupLoop()
	return l
}

// cleanupLoop evicts idle buckets to prevent unbounded memory growth.
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for ip, b := range l.buckets {
			b.mu.Lock()
			idle := now.Sub(b.lastRefill) > 10*time.Minute
			b.mu.Unlock()
			if idle {
				delete(l.buckets, ip)
			}
		}
		l.mu.Unlock()
	}
}

func (l *Limiter) getBucket(ip string) *bucket {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{
			tokens:     l.rate,
			lastRefill: time.Now(),
		}
		l.buckets[ip] = b
	}
	return b
}

// Allow returns true if the request from ip should be allowed.
func (l *Limiter) Allow(ip string) bool {
	b := l.getBucket(ip)
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now

	// Refill tokens, capped at the burst size (= rate, one second worth)
	b.tokens += elapsed * l.rate
	if b.tokens > l.rate {
		b.tokens = l.rate
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Middleware is a chi-compatible middleware that rate limits by client IP.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !l.Allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// extractIP strips the port from r.RemoteAddr (and respects X-Real-IP set by
// trusted proxies via chi's RealIP middleware, which rewrites RemoteAddr).
func extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
