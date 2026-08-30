package audit

import (
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/domainerr"
)

func (r *Ring) EmitDenied(actor auth.Actor, capability string, err error) {
	r.Emit(Event{
		ActorID:    actor.ID,
		ActorClass: actor.Class,
		Capability: capability,
		Result:     ResultDenied,
		ErrorCode:  domainerr.CodeOf(err),
	})
}

func (r *Ring) EmitOK(actor auth.Actor, capability, reason, revision, previous string) string {
	return r.Emit(Event{
		ActorID:    actor.ID,
		ActorClass: actor.Class,
		Capability: capability,
		Reason:     reason,
		Revision:   revision,
		Previous:   previous,
		Result:     ResultOK,
	})
}
