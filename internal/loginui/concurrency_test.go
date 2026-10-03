package loginui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPasswordConcurrencyAdmission(t *testing.T) {
	u := &UI{verifies: make(chan struct{}, 4)}
	for range 4 {
		u.verifies <- struct{}{}
	}
	rec := httptest.NewRecorder()
	u.postLogin(rec, httptest.NewRequest("POST", "/login", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatal("password concurrency unbounded")
	}
}
