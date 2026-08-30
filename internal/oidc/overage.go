package oidc

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

func groupClaims(snap *snapshot.Snapshot, user model.User, warn func(string)) (map[string]any, error) {
	ids := append([]string(nil), user.GroupIDs...)
	sort.Strings(ids)
	names := make([]string, 0, len(ids))
	for _, gid := range ids {
		if g, ok := snap.GroupsByID[gid]; ok && g.Name != "" {
			names = append(names, g.Name)
		} else {
			names = append(names, gid)
		}
	}
	n := len(ids)
	ov := model.GroupOverage{OktaFailAt: 100, GenericCap: 200}
	if snap.Canonical != nil {
		ov = snap.Canonical.Spec.GroupOverage
		if ov.OktaFailAt < 1 {
			ov.OktaFailAt = 100
		}
		if ov.GenericCap < 1 {
			ov.GenericCap = 200
		}
	}
	vendor := ""
	if snap != nil {
		vendor = snap.Clothes.Vendor
	}
	switch vendor {
	case "okta":
		if n >= ov.OktaFailAt {
			return nil, fmt.Errorf("okta overage")
		}
		return map[string]any{"groups": names}, nil
	case "entra":
		if n > ov.GenericCap {
			if !ov.EntraGraphStub {
				return nil, fmt.Errorf("entra stub disabled")
			}
			iss := strings.TrimRight(snap.Issuer, "/")
			endpoint := iss + "/v1.0/users/" + user.ID + "/getMemberGroups"
			return map[string]any{
				"_claim_names":   map[string]string{"groups": "src1"},
				"_claim_sources": map[string]any{"src1": map[string]string{"endpoint": endpoint}},
			}, nil
		}
		return map[string]any{"groups": names}, nil
	default:
		if n > ov.GenericCap {
			if warn != nil {
				warn(fmt.Sprintf("generic overage omitted %d groups (cap %d)", n-ov.GenericCap, ov.GenericCap))
			}
			names = names[:ov.GenericCap]
		}
		return map[string]any{"groups": names}, nil
	}
}
