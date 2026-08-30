package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

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
	b, err := json.Marshal(struct {
		Expected string            `json:"expectedRevision"`
		Reason   string            `json:"reason"`
		Ops      []model.Operation `json:"operations"`
	}{in.ExpectedRevision, in.Reason, in.Operations})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
