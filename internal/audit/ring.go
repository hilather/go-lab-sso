package audit

import (
	"sync"
	"time"
)

type Event struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"time"`
	ActorID    string    `json:"actorId"`
	ActorClass string    `json:"actorClass"`
	Capability string    `json:"capability"`
	Reason     string    `json:"reason,omitempty"`
	Revision   string    `json:"revision,omitempty"`
	Previous   string    `json:"previousRevision,omitempty"`
	Result     string    `json:"result"`
	ErrorCode  string    `json:"errorCode,omitempty"`
}

const ResultOK = "ok"
const ResultDenied = "denied"
const ResultError = "error"

type Ring struct {
	mu  sync.Mutex
	cap int
	seq int
	buf []Event
}

func NewRing(n int) *Ring {
	if n <= 0 {
		n = 256
	}
	return &Ring{cap: n}
}

func (r *Ring) Emit(e Event) string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	if e.ID == "" {
		e.ID = "evt-" + time.Now().UTC().Format("20060102T150405") + "-" + itoa(r.seq)
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	r.buf = append(r.buf, e)
	if len(r.buf) > r.cap {
		r.buf = r.buf[len(r.buf)-r.cap:]
	}
	return e.ID
}

func (r *Ring) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buf)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
