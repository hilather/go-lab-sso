package oidc

import "net/http"

// SetReject installs a redacted security-event callback at application construction.
func (r *Runtime) SetReject(fn func(string)) { r.mu.Lock(); defer r.mu.Unlock(); r.reject = fn }
func (r *Runtime) Reject(reason string) {
	r.mu.Lock()
	fn := r.reject
	r.mu.Unlock()
	if fn != nil {
		fn(reason)
	}
}

type rejectWriter struct {
	http.ResponseWriter
	status int
}

func (w *rejectWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *rejectWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(b)
}

// AuditRejected records only fixed protocol/category names, never request or response payloads.
func (r *Runtime) AuditRejected(category string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rw := &rejectWriter{ResponseWriter: w}
		next.ServeHTTP(rw, req)
		if rw.status >= 400 {
			r.Reject(category)
		}
	})
}
