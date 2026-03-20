// Teleport
// Copyright (C) 2026 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/lib/auth/mfatypes"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/services"
)

// BeginBrowserMFAChallenge creates a new Browser MFA auth request and session
// data for the given params and stores it in the backend.
func (a *Server) BeginBrowserMFAChallenge(ctx context.Context, params mfatypes.BeginBrowserMFAChallengeParams) (*proto.BrowserMFAChallenge, error) {
	if err := sso.ValidateClientRedirect(params.BrowserMFATSHRedirectURL, sso.CeremonyTypeMFA, nil); err != nil {
		return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
	}

	requestID := uuid.NewString()
	browserChal := &proto.BrowserMFAChallenge{
		RequestId: requestID,
	}

	sessionData := &services.MFASessionData{
		Username:       params.User,
		RequestID:      requestID,
		ConnectorID:    constants.BrowserMFA,
		ConnectorType:  constants.BrowserMFA,
		TSHRedirectURL: params.BrowserMFATSHRedirectURL,
		ChallengeExtensions: &mfatypes.ChallengeExtensions{
			Scope:      params.Ext.Scope,
			AllowReuse: params.Ext.AllowReuse,
		},
		SourceCluster: params.SourceCluster,
		TargetCluster: params.TargetCluster,
		Payload: &mfatypes.SessionIdentifyingPayload{
			SSHSessionID: params.SIP.GetSshSessionId(),
		},
	}

	if err := a.UpsertMFASessionData(ctx, sessionData); err != nil {
		return nil, trace.Wrap(err)
	}

	return browserChal, nil
}
