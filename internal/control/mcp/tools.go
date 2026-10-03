package mcp

import (
	"context"
	"encoding/json"
	"github.com/hilather/go-lab-sso/internal/contracts"
	"strings"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type emptyIn struct{}

type reasonIn struct {
	Reason string `json:"reason,omitempty"`
}

type idIn struct {
	ID string `json:"id"`
}

type mcpOp struct {
	Op     model.OpKind    `json:"op"`
	Target model.Target    `json:"target"`
	Value  json.RawMessage `json:"value,omitempty"`
}

type changeIn struct {
	ExpectedRevision string  `json:"expectedRevision"`
	IdempotencyKey   string  `json:"idempotencyKey,omitempty"`
	Reason           string  `json:"reason,omitempty"`
	Operations       []mcpOp `json:"operations,omitempty"`
}

func (in changeIn) toApp() (app.ChangeIn, error) {
	ops := make([]model.Operation, len(in.Operations))
	for i, op := range in.Operations {
		var raw json.RawMessage
		if op.Value != nil {
			b, err := json.Marshal(op.Value)
			if err != nil {
				return app.ChangeIn{}, err
			}
			raw = b
		}
		ops[i] = model.Operation{Op: op.Op, Target: op.Target, Value: raw}
	}
	return app.ChangeIn{
		ExpectedRevision: in.ExpectedRevision,
		IdempotencyKey:   in.IdempotencyKey,
		Reason:           in.Reason,
		Operations:       ops,
	}, nil
}

type validateIn struct {
	Document         *model.Document `json:"document,omitempty"`
	ExpectedRevision string          `json:"expectedRevision,omitempty"`
	Reason           string          `json:"reason,omitempty"`
	IdempotencyKey   string          `json:"idempotencyKey,omitempty"`
	Operations       []mcpOp         `json:"operations,omitempty"`
}

type resetIn struct {
	ExpectedRevision string `json:"expectedRevision,omitempty"`
	IdempotencyKey   string `json:"idempotencyKey,omitempty"`
	DryRun           bool   `json:"dryRun,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

func (s *Server) registerTools() {
	add(s, "sso_version_get", false, true, func(ctx context.Context, actor auth.Actor, _ emptyIn) (any, error) {
		return s.app.Version(actor)
	})
	add(s, "sso_capabilities_get", false, true, func(ctx context.Context, actor auth.Actor, _ emptyIn) (any, error) {
		return s.app.Capabilities(actor)
	})
	add(s, "sso_status_get", false, true, func(ctx context.Context, actor auth.Actor, _ emptyIn) (any, error) {
		return s.app.GetStatus(actor)
	})
	add(s, "sso_schema_get", false, true, func(ctx context.Context, actor auth.Actor, _ emptyIn) (any, error) {
		return s.app.SchemaConfig(actor)
	})
	add(s, "sso_state_get", false, true, func(ctx context.Context, actor auth.Actor, _ emptyIn) (any, error) {
		return s.app.GetState(actor)
	})
	add(s, "sso_state_validate", false, true, func(ctx context.Context, actor auth.Actor, in validateIn) (any, error) {
		cin, err := (changeIn{Operations: in.Operations}).toApp()
		if err != nil {
			return nil, err
		}
		return s.app.Validate(actor, app.ValidateIn{Document: in.Document, Operations: cin.Operations})
	})
	add(s, "sso_change_plan", false, true, func(ctx context.Context, actor auth.Actor, in changeIn) (any, error) {
		cin, err := in.toApp()
		if err != nil {
			return nil, err
		}
		return s.app.Plan(actor, cin)
	})
	add(s, "sso_change_apply", true, true, func(ctx context.Context, actor auth.Actor, in changeIn) (any, error) {
		cin, err := in.toApp()
		if err != nil {
			return nil, err
		}
		return s.app.Apply(actor, cin)
	})
	add(s, "sso_state_export", false, true, func(ctx context.Context, actor auth.Actor, in struct {
		Format string `json:"format,omitempty"`
	}) (any, error) {
		ex, err := s.app.Export(actor, in.Format)
		if err != nil {
			return nil, err
		}
		if ex.Format == "json" {
			return map[string]any{"format": ex.Format, "json": json.RawMessage(ex.Data), "revision": ex.Revision}, nil
		}
		return map[string]any{"format": ex.Format, "yaml": string(ex.Data), "revision": ex.Revision}, nil
	})
	add(s, "sso_state_reset", true, false, func(ctx context.Context, actor auth.Actor, in resetIn) (any, error) {
		return s.app.Reset(actor, app.ResetIn{Reason: in.Reason, ExpectedRevision: in.ExpectedRevision, IdempotencyKey: in.IdempotencyKey, DryRun: in.DryRun})
	})
	add(s, "sso_clients_list", false, true, func(ctx context.Context, actor auth.Actor, in app.ListIn) (any, error) {
		return s.app.PageClients(actor, in)
	})
	add(s, "sso_client_get", false, true, func(ctx context.Context, actor auth.Actor, in idIn) (any, error) {
		return s.app.GetClient(actor, in.ID)
	})
	add(s, "sso_users_list", false, true, func(ctx context.Context, actor auth.Actor, in app.ListIn) (any, error) {
		return s.app.PageUsers(actor, in)
	})
	add(s, "sso_user_get", false, true, func(ctx context.Context, actor auth.Actor, in idIn) (any, error) {
		return s.app.GetUser(actor, in.ID)
	})
	add(s, "sso_auth_mfa_set", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		Mode             string `json:"mode"`
		ExpectedRevision string `json:"expectedRevision"`
		IdempotencyKey   string `json:"idempotencyKey,omitempty"`
		Reason           string `json:"reason,omitempty"`
	}) (any, error) {
		return s.app.SetMFA(actor, app.SetMFAIn{
			Mode: in.Mode, ExpectedRevision: in.ExpectedRevision,
			IdempotencyKey: in.IdempotencyKey, Reason: in.Reason,
		})
	})
	add(s, "sso_user_totp_enroll", true, false, func(ctx context.Context, actor auth.Actor, in struct {
		ID     string `json:"id"`
		Reason string `json:"reason,omitempty"`
	}) (any, error) {
		return s.app.EnrollTOTP(actor, in.ID, in.Reason)
	})
	add(s, "sso_user_totp_clear", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		ID     string `json:"id"`
		Reason string `json:"reason,omitempty"`
	}) (any, error) {
		return map[string]any{"ok": true}, s.app.ClearTOTP(actor, in.ID, in.Reason)
	})
	add(s, "sso_groups_list", false, true, func(ctx context.Context, actor auth.Actor, in app.ListIn) (any, error) {
		return s.app.PageGroups(actor, in)
	})
	add(s, "sso_group_get", false, true, func(ctx context.Context, actor auth.Actor, in idIn) (any, error) {
		return s.app.GetGroup(actor, in.ID)
	})
	add(s, "sso_sessions_list", false, true, func(ctx context.Context, actor auth.Actor, in app.ListIn) (any, error) {
		return s.app.PageSessions(actor, in)
	})
	add(s, "sso_session_expire", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		ID     string `json:"id"`
		Reason string `json:"reason,omitempty"`
	}) (any, error) {
		return map[string]any{"ok": true}, s.app.ExpireSession(actor, in.ID, in.Reason)
	})
	add(s, "sso_tunable_token_pause", true, true, func(ctx context.Context, actor auth.Actor, in reasonIn) (any, error) {
		return map[string]any{"paused": true}, s.app.PauseToken(actor, in.Reason)
	})
	add(s, "sso_tunable_token_resume", true, true, func(ctx context.Context, actor auth.Actor, in reasonIn) (any, error) {
		return map[string]any{"paused": false}, s.app.ResumeToken(actor, in.Reason)
	})
	add(s, "sso_tunable_auth_force_fail", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		Reason string `json:"reason,omitempty"`
		On     bool   `json:"on"`
	}) (any, error) {
		return map[string]any{"on": in.On}, s.app.ForceFail(actor, in.On, in.Reason)
	})
	add(s, "sso_tunable_error_inject", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		Reason string `json:"reason,omitempty"`
		Code   string `json:"code,omitempty"`
	}) (any, error) {
		return map[string]any{"code": in.Code}, s.app.InjectError(actor, in.Code, in.Reason)
	})
	add(s, "sso_tunable_vendor_swap", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		Vendor           string  `json:"vendor"`
		TenantID         *string `json:"tenantId,omitempty"`
		ExpectedRevision string  `json:"expectedRevision"`
		IdempotencyKey   string  `json:"idempotencyKey,omitempty"`
		Reason           string  `json:"reason,omitempty"`
	}) (any, error) {
		return s.app.SwapVendor(actor, app.SwapVendorIn{
			Vendor: in.Vendor, TenantID: in.TenantID,
			ExpectedRevision: in.ExpectedRevision, IdempotencyKey: in.IdempotencyKey, Reason: in.Reason,
		})
	})
	add(s, "sso_tunable_overage_set", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		EntraGraphStub   *bool  `json:"entraGraphStub,omitempty"`
		OktaFailAt       *int   `json:"oktaFailAt,omitempty"`
		GenericCap       *int   `json:"genericCap,omitempty"`
		ExpectedRevision string `json:"expectedRevision"`
		IdempotencyKey   string `json:"idempotencyKey,omitempty"`
		Reason           string `json:"reason,omitempty"`
	}) (any, error) {
		return s.app.SetOverage(actor, app.SetOverageIn{
			EntraGraphStub: in.EntraGraphStub, OktaFailAt: in.OktaFailAt, GenericCap: in.GenericCap,
			ExpectedRevision: in.ExpectedRevision, IdempotencyKey: in.IdempotencyKey, Reason: in.Reason,
		})
	})
	add(s, "sso_tunable_consent_force", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		Reason string `json:"reason,omitempty"`
		On     bool   `json:"on"`
	}) (any, error) {
		return map[string]any{"on": in.On}, s.app.ForceConsent(actor, in.On, in.Reason)
	})
	add(s, "sso_tunable_token_mint", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		UserID   string `json:"userId"`
		ClientID string `json:"clientId"`
		Scope    string `json:"scope,omitempty"`
	}) (any, error) {
		return s.app.MintToken(actor, app.MintTokenIn{UserID: in.UserID, ClientID: in.ClientID, Scope: in.Scope})
	})
	add(s, "sso_audit_query", false, true, func(ctx context.Context, actor auth.Actor, in app.ListIn) (any, error) {
		return s.app.PageAudit(actor, in)
	})
	add(s, "sso_audit_get", false, true, func(ctx context.Context, actor auth.Actor, in idIn) (any, error) {
		return s.app.GetAudit(actor, in.ID)
	})
	add(s, "sso_import_plan", false, true, func(ctx context.Context, actor auth.Actor, in struct {
		Kind     string `json:"kind"`
		Document string `json:"document"`
		Reason   string `json:"reason,omitempty"`
	}) (any, error) {
		return s.app.ImportPlan(actor, app.ImportIn{Kind: in.Kind, Document: in.Document, Reason: in.Reason})
	})
	add(s, "sso_import_apply", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		Kind             string `json:"kind"`
		Document         string `json:"document"`
		ExpectedRevision string `json:"expectedRevision"`
		IdempotencyKey   string `json:"idempotencyKey,omitempty"`
		Reason           string `json:"reason,omitempty"`
	}) (any, error) {
		return s.app.ImportApply(actor, app.ImportIn{
			Kind: in.Kind, Document: in.Document, ExpectedRevision: in.ExpectedRevision,
			IdempotencyKey: in.IdempotencyKey, Reason: in.Reason,
		})
	})
	add(s, "sso_tunable_redirect_rewrite", true, true, func(ctx context.Context, actor auth.Actor, in struct {
		ClientID         string   `json:"clientId"`
		RedirectURIs     []string `json:"redirectURIs"`
		ExpectedRevision string   `json:"expectedRevision"`
		IdempotencyKey   string   `json:"idempotencyKey,omitempty"`
		Reason           string   `json:"reason,omitempty"`
	}) (any, error) {
		return s.app.RewriteRedirect(actor, app.RewriteRedirectIn{
			ClientID: in.ClientID, RedirectURIs: in.RedirectURIs,
			ExpectedRevision: in.ExpectedRevision, IdempotencyKey: in.IdempotencyKey, Reason: in.Reason,
		})
	})
	add(s, "sso_sessions_expire_all", true, true, func(ctx context.Context, actor auth.Actor, in reasonIn) (any, error) {
		n, err := s.app.ExpireAllSessions(actor, in.Reason)
		return map[string]any{"expired": n}, err
	})
}

func add[In any](s *Server, name string, mutating, idempotent bool, h func(context.Context, auth.Actor, In) (any, error)) {
	ro := !mutating
	var inputSchema any
	switch name {
	case "sso_clients_list", "sso_users_list", "sso_groups_list", "sso_sessions_list", "sso_audit_query":
		inputSchema = contracts.ListSchema()
	case "sso_state_validate":
		inputSchema = contracts.ChangeSchema(true)
	case "sso_change_plan", "sso_change_apply":
		inputSchema = contracts.ChangeSchema(false)
	}
	sdk.AddTool(s.sdk, &sdk.Tool{
		InputSchema: inputSchema,
		Name:        name,
		Title:       name,
		Description: name,
		Annotations: &sdk.ToolAnnotations{
			Title:          name,
			ReadOnlyHint:   ro,
			IdempotentHint: idempotent,
			OpenWorldHint:  boolPtr(false),
		},
	}, func(ctx context.Context, req *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
		// The SDK schema pass uses generic JSON numbers; decode the original bytes
		// into domain inputs so integer and RawMessage values retain exact precision.
		if req != nil && req.Params != nil && len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
				return nil, nil, domainerr.Validation("invalid arguments: " + err.Error())
			}
		}
		out, err := h(ctx, actorFrom(ctx), in)
		if err != nil {
			code := domainerr.CodeOf(err)
			if code == "" {
				code = domainerr.CodeInternal
			}
			return &sdk.CallToolResult{
				IsError: true,
				Content: []sdk.Content{&sdk.TextContent{Text: err.Error()}},
				StructuredContent: map[string]any{
					"code":   code,
					"detail": err.Error(),
				},
			}, nil, nil
		}
		return nil, out, nil
	})
}

func boolPtr(v bool) *bool { return &v }

func (s *Server) registerResources() {
	h := s.readResource
	for _, uri := range []string{
		"labsso://state",
		"labsso://capabilities",
		"labsso://status",
		"labsso://schema/config",
		"labsso://audit/recent",
	} {
		s.sdk.AddResource(&sdk.Resource{
			URI: uri, Name: uri, MIMEType: "application/json",
			Description: uri,
		}, h)
	}
	for _, tmpl := range []string{
		"labsso://clients/{id}",
		"labsso://users/{id}",
		"labsso://groups/{id}",
	} {
		s.sdk.AddResourceTemplate(&sdk.ResourceTemplate{
			URITemplate: tmpl, Name: tmpl, MIMEType: "application/json",
			Description: tmpl,
		}, h)
	}
}

func (s *Server) readResource(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
	actor := actorFrom(ctx)
	uri := ""
	if req != nil && req.Params != nil {
		uri = req.Params.URI
	}
	var (
		out any
		err error
	)
	switch {
	case uri == "labsso://state":
		out, err = s.app.GetState(actor)
	case uri == "labsso://capabilities":
		out, err = s.app.Capabilities(actor)
	case uri == "labsso://status":
		out, err = s.app.GetStatus(actor)
	case uri == "labsso://schema/config":
		out, err = s.app.SchemaConfig(actor)
	case uri == "labsso://audit/recent":
		out, err = s.app.PageAudit(actor, app.ListIn{})
	case strings.HasPrefix(uri, "labsso://clients/"):
		out, err = s.app.GetClient(actor, strings.TrimPrefix(uri, "labsso://clients/"))
	case strings.HasPrefix(uri, "labsso://users/"):
		out, err = s.app.GetUser(actor, strings.TrimPrefix(uri, "labsso://users/"))
	case strings.HasPrefix(uri, "labsso://groups/"):
		out, err = s.app.GetGroup(actor, strings.TrimPrefix(uri, "labsso://groups/"))
	default:
		return nil, resourceError(domainerr.NotFound("resource " + uri))
	}
	if err != nil {
		return nil, resourceError(err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, resourceError(err)
	}
	return &sdk.ReadResourceResult{
		Contents: []*sdk.ResourceContents{{
			URI: uri, MIMEType: "application/json", Text: string(b),
		}},
	}, nil
}

func resourceError(err error) error {
	code := domainerr.CodeOf(err)
	if code == "" {
		code = "internal"
	}
	data, _ := json.Marshal(map[string]string{"code": code})
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: err.Error(), Data: data}
}
