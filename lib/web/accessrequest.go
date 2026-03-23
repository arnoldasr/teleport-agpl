/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package web

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	proto "github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/httplib"
)

type accessRequestListItem struct {
	ID          string    `json:"id"`
	State       string    `json:"state"`
	User        string    `json:"user"`
	Roles       []string  `json:"roles"`
	Reason      string    `json:"reason"`
	Created     time.Time `json:"created"`
	Expires     time.Time `json:"expires"`
	ResolveReason string  `json:"resolveReason,omitempty"`
}

func stateToString(s types.RequestState) string {
	switch s {
	case types.RequestState_PENDING:
		return "PENDING"
	case types.RequestState_APPROVED:
		return "APPROVED"
	case types.RequestState_DENIED:
		return "DENIED"
	case types.RequestState_NONE:
		return "NONE"
	default:
		return "UNKNOWN"
	}
}

func (h *Handler) getAccessRequests(w http.ResponseWriter, r *http.Request, params httprouter.Params, ctx *SessionContext) (interface{}, error) {
	clt, err := ctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	requests, err := clt.GetAccessRequests(r.Context(), types.AccessRequestFilter{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	items := make([]accessRequestListItem, 0, len(requests))
	for _, req := range requests {
		items = append(items, accessRequestListItem{
			ID:            req.GetName(),
			State:         stateToString(req.GetState()),
			User:          req.GetUser(),
			Roles:         req.GetRoles(),
			Reason:        req.GetRequestReason(),
			Created:       req.GetCreationTime(),
			Expires:       req.Expiry(),
			ResolveReason: req.GetResolveReason(),
		})
	}

	return items, nil
}

type createAccessRequestReq struct {
	Roles  []string `json:"roles"`
	Reason string   `json:"reason"`
}

func (h *Handler) createAccessRequest(w http.ResponseWriter, r *http.Request, params httprouter.Params, ctx *SessionContext) (interface{}, error) {
	clt, err := ctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var req createAccessRequestReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	accessReq, err := types.NewAccessRequest(uuid.New().String(), ctx.GetUser(), req.Roles...)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	accessReq.SetRequestReason(req.Reason)

	created, err := clt.CreateAccessRequestV2(r.Context(), accessReq)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return accessRequestListItem{
		ID:      created.GetName(),
		State:   stateToString(created.GetState()),
		User:    created.GetUser(),
		Roles:   created.GetRoles(),
		Reason:  created.GetRequestReason(),
		Created: created.GetCreationTime(),
		Expires: created.Expiry(),
	}, nil
}

type reviewAccessRequestReq struct {
	Reason string `json:"reason"`
}

func (h *Handler) approveAccessRequest(w http.ResponseWriter, r *http.Request, params httprouter.Params, ctx *SessionContext) (interface{}, error) {
	clt, err := ctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var req reviewAccessRequestReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	err = clt.SetAccessRequestState(r.Context(), types.AccessRequestUpdate{
		RequestID: params.ByName("id"),
		State:     types.RequestState_APPROVED,
		Reason:    req.Reason,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return OK(), nil
}

func (h *Handler) denyAccessRequest(w http.ResponseWriter, r *http.Request, params httprouter.Params, ctx *SessionContext) (interface{}, error) {
	clt, err := ctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var req reviewAccessRequestReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	err = clt.SetAccessRequestState(r.Context(), types.AccessRequestUpdate{
		RequestID: params.ByName("id"),
		State:     types.RequestState_DENIED,
		Reason:    req.Reason,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return OK(), nil
}

func (h *Handler) deleteAccessRequest(w http.ResponseWriter, r *http.Request, params httprouter.Params, ctx *SessionContext) (interface{}, error) {
	clt, err := ctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := clt.DeleteAccessRequest(r.Context(), params.ByName("id")); err != nil {
		return nil, trace.Wrap(err)
	}

	return OK(), nil
}

type requestableRolesResponse struct {
	Roles []string `json:"roles"`
}

func (h *Handler) getRequestableRoles(w http.ResponseWriter, r *http.Request, params httprouter.Params, ctx *SessionContext) (interface{}, error) {
	clt, err := ctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := clt.ListRequestableRoles(r.Context(), &proto.ListRequestableRolesRequest{})
	if err != nil {
		// Fallback: try listing all roles if the user has permission
		roles, err2 := clt.GetRoles(r.Context())
		if err2 != nil {
			return nil, trace.Wrap(err)
		}
		var roleNames []string
		for _, role := range roles {
			roleNames = append(roleNames, role.GetName())
		}
		return requestableRolesResponse{Roles: roleNames}, nil
	}

	var roleNames []string
	for _, role := range resp.Roles {
		roleNames = append(roleNames, role.Name)
	}
	return requestableRolesResponse{Roles: roleNames}, nil
}
