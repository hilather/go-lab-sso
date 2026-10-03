package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/hilather/go-lab-sso/internal/auth"

	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
)

type idempEntry struct {
	key  string
	fp   string
	plan *Plan
	res  *ApplyResult
}

type idempCache struct {
	cap   int
	order []string
	m     map[string]idempEntry
}

func newIdemp(n int) *idempCache {
	return &idempCache{cap: n, m: map[string]idempEntry{}}
}

func (c *idempCache) lookup(key, fp string) (*idempEntry, error) {
	if key == "" || c == nil {
		return nil, nil
	}
	e, ok := c.m[key]
	if !ok {
		return nil, nil
	}
	if e.fp != fp {
		return nil, domainerr.Conflict("idempotency key reused with a different request")
	}
	for i, k := range c.order {
		if k == key {
			c.order = append(append(c.order[:i:i], c.order[i+1:]...), key)
			break
		}
	}
	return &e, nil
}

func (c *idempCache) store(key, fp string, plan *Plan, res *ApplyResult) {
	if key == "" || c == nil {
		return
	}
	if _, ok := c.m[key]; !ok {
		c.order = append(c.order, key)
		if len(c.order) > c.cap {
			old := c.order[0]
			c.order = c.order[1:]
			delete(c.m, old)
		}
	}
	c.m[key] = idempEntry{key: key, fp: fp, plan: plan, res: res}
}

func (c *idempCache) clear() {
	if c == nil {
		return
	}
	c.order = nil
	c.m = map[string]idempEntry{}
}

func fingerprintChange(in ChangeIn) (string, error) {
	if in.fingerprint != "" {
		return in.fingerprint, nil
	}
	b, err := json.Marshal(struct {
		Expected string            `json:"expectedRevision"`
		Reason   string            `json:"reason"`
		Ops      []model.Operation `json:"operations"`
	}{in.ExpectedRevision, in.Reason, in.Operations})
	if err != nil {
		return "", err
	}
	return fingerprintInput(json.RawMessage(b))
}

func fingerprintInput(in any) (string, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	var canonical any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&canonical); err != nil {
		return "", err
	}
	b, err = json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func scopedKey(actor auth.Actor, capID, key string) string {
	if key == "" {
		return ""
	}
	b, _ := json.Marshal([]string{actor.Class, actor.ID, capID, key})
	return string(b)
}
func (a *App) replayTyped(actor auth.Actor, capID, key string, in any) (*ApplyResult, string, error) {
	fp, err := fingerprintInput(in)
	if err != nil {
		return nil, "", err
	}
	hit, err := a.idemp.lookup(scopedKey(actor, capID, key), fp)
	if err != nil {
		return nil, "", err
	}
	if hit != nil && hit.res != nil {
		out := *hit.res
		return &out, fp, nil
	}
	return nil, fp, nil
}
