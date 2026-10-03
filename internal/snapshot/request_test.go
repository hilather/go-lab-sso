package snapshot

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCaptureRetainsRequestSnapshot(t *testing.T) {
	st := NewStore()
	first := &Snapshot{Revision: "first"}
	second := &Snapshot{Revision: "second"}
	st.Swap(first)
	h := Capture(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.Swap(second)
		if FromRequest(r, st) != first {
			t.Fatal("request reloads active state")
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://lab.example/", nil))
	if FromRequest(httptest.NewRequest("GET", "/", nil), st) != second {
		t.Fatal("new request must capture new state")
	}
}
