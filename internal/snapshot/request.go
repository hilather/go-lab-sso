package snapshot

import (
	"context"
	"net/http"
)

type requestKey struct{}

func FromRequest(r *http.Request, store *Store) *Snapshot {
	if s, ok := r.Context().Value(requestKey{}).(*Snapshot); ok {
		return s
	}
	return store.Load()
}
func Capture(store *Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := FromRequest(r, store)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestKey{}, s)))
	})
}
