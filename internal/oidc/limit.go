package oidc

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cut := now.Add(-l.window)
	for k, hits := range l.hits {
		if len(hits) == 0 || !hits[len(hits)-1].After(cut) {
			delete(l.hits, k)
		}
	}
	if _, exists := l.hits[key]; !exists && len(l.hits) >= 4096 {
		return false
	}
	cur := l.hits[key]
	kept := cur[:0]
	for _, t := range cur {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.n {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
