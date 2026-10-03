package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-sso/internal/audit"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
)

type ListIn struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}

func page[T any](items []T, in ListIn, kind string, id func(T) string) (*Page[T], error) {
	if in.Limit < 0 || in.Limit > 1000 {
		return nil, domainerr.Validation("limit must be between 1 and 1000")
	}
	limit := in.Limit
	if limit == 0 {
		limit = 100
	}
	sort.Slice(items, func(i, j int) bool { return id(items[i]) < id(items[j]) })
	raw, _ := json.Marshal(items)
	digest := sha256.Sum256(raw)
	scope := kind + ":" + hex.EncodeToString(digest[:])
	offset := 0
	if in.Cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(in.Cursor)
		if err != nil {
			return nil, domainerr.Validation("invalid cursor")
		}
		parts := strings.Split(string(b), "|")
		if len(parts) != 2 || parts[0] != scope {
			return nil, domainerr.Validation("invalid or stale cursor")
		}
		offset, err = strconv.Atoi(parts[1])
		if err != nil || offset < 0 || offset >= len(items) {
			return nil, domainerr.Validation("invalid cursor")
		}
	}
	end := min(offset+limit, len(items))
	out := &Page[T]{Items: append([]T{}, items[offset:end]...)}
	if end < len(items) {
		out.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(scope + "|" + strconv.Itoa(end)))
	}
	return out, nil
}
func (a *App) PageClients(actor auth.Actor, in ListIn) (*Page[model.Client], error) {
	items, err := a.ListClients(actor)
	if err != nil {
		return nil, err
	}
	return page(items, in, "clients", func(v model.Client) string { return v.ID })
}
func (a *App) PageUsers(actor auth.Actor, in ListIn) (*Page[UserView], error) {
	items, err := a.ListUsers(actor)
	if err != nil {
		return nil, err
	}
	return page(items, in, "users", func(v UserView) string { return v.ID })
}
func (a *App) PageGroups(actor auth.Actor, in ListIn) (*Page[model.Group], error) {
	items, err := a.ListGroups(actor)
	if err != nil {
		return nil, err
	}
	return page(items, in, "groups", func(v model.Group) string { return v.ID })
}
func (a *App) PageSessions(actor auth.Actor, in ListIn) (*Page[oidc.LoginSession], error) {
	items, err := a.ListSessions(actor)
	if err != nil {
		return nil, err
	}
	return page(items, in, "sessions", func(v oidc.LoginSession) string { return v.ID })
}
func (a *App) PageAudit(actor auth.Actor, in ListIn) (*Page[audit.Event], error) {
	items, err := a.ListAudit(actor)
	if err != nil {
		return nil, err
	}
	return page(items, in, "audit", func(v audit.Event) string { return v.ID })
}
