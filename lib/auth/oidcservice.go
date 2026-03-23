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

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v3/jwt"
	"github.com/gravitational/trace"
	"golang.org/x/oauth2"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/utils/keys/hardwarekey"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// AGPLOIDCService implements the OIDCService interface for the AGPL build.
// It handles the OIDC authentication flow: creating auth requests and
// validating callbacks from OIDC providers.
type AGPLOIDCService struct {
	a *Server
}

// NewAGPLOIDCService creates a new OIDC service implementation.
func NewAGPLOIDCService(a *Server) *AGPLOIDCService {
	return &AGPLOIDCService{a: a}
}

// CreateOIDCAuthRequest creates a new OIDC auth request and returns it with
// the redirect URL to the OIDC provider.
func (s *AGPLOIDCService) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, err := s.getOIDCConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	oauthConfig, err := s.newOAuth2Config(connector, redirectURL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	stateToken, err := utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req.StateToken = stateToken

	// Build OAuth2 options
	var opts []oauth2.AuthCodeOption
	if connector.GetPrompt() != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", connector.GetPrompt()))
	}
	if connector.GetACR() != "" {
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", connector.GetACR()))
	}

	req.RedirectURL = oauthConfig.AuthCodeURL(stateToken, opts...)
	s.a.logger.DebugContext(ctx, "Creating OIDC auth request",
		"connector", connector.GetName(),
		"redirect_url", req.RedirectURL,
	)

	err = s.a.Services.CreateOIDCAuthRequest(ctx, req, defaults.OIDCAuthRequestTTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// CreateOIDCAuthRequestForMFA creates an OIDC auth request for MFA validation.
func (s *AGPLOIDCService) CreateOIDCAuthRequestForMFA(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	// For MFA, use the same flow as regular auth requests.
	return s.CreateOIDCAuthRequest(ctx, req)
}

// ValidateOIDCAuthCallback handles the callback from the OIDC provider,
// exchanges the code for tokens, validates them, and creates the user session.
func (s *AGPLOIDCService) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	logger := s.a.logger.With(teleport.ComponentKey, "oidc")

	diagCtx := NewSSODiagContext(types.KindOIDC, s.a)

	resp, err := s.validateOIDCAuthCallback(ctx, diagCtx, q, logger)

	diagCtx.Info.Error = trace.UserMessage(err)
	diagCtx.WriteToBackend(ctx)

	event := &apievents.UserLogin{
		Metadata: apievents.Metadata{
			Type: events.UserLoginEvent,
		},
		Method: events.LoginMethodOIDC,
	}

	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		if diagCtx.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginFailureCode
		}
		event.Status = apievents.Status{
			Success:     false,
			Error:       trace.Unwrap(err).Error(),
			UserMessage: err.Error(),
		}
		if err := s.a.emitter.EmitAuditEvent(ctx, event); err != nil {
			logger.WarnContext(ctx, "Failed to emit OIDC login failure event", "error", err)
		}
		return nil, trace.Wrap(err)
	}

	event.Code = events.UserSSOLoginCode
	if diagCtx.Info.TestFlow {
		event.Code = events.UserSSOTestFlowLoginCode
	}
	event.User = resp.Username
	event.Status = apievents.Status{Success: true}
	if err := s.a.emitter.EmitAuditEvent(ctx, event); err != nil {
		logger.WarnContext(ctx, "Failed to emit OIDC login event", "error", err)
	}

	return resp, nil
}

func (s *AGPLOIDCService) validateOIDCAuthCallback(ctx context.Context, diagCtx *SSODiagContext, q url.Values, logger *slog.Logger) (*authclient.OIDCAuthResponse, error) {
	if errParam := q.Get("error"); errParam != "" {
		state := q.Get("state")
		if state != "" {
			diagCtx.RequestID = state
			req, err := s.a.Services.GetOIDCAuthRequest(ctx, state)
			if err == nil {
				diagCtx.Info.TestFlow = req.SSOTestFlow
			}
		}
		errDesc := q.Get("error_description")
		oauthErr := trace.OAuth2("invalid_request", errParam, q)
		return nil, trace.WithUserMessage(oauthErr, "OIDC provider returned error: %v [%v]", errDesc, errParam)
	}

	code := q.Get("code")
	if code == "" {
		oauthErr := trace.OAuth2("invalid_request", "code query param must be set", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from OIDC provider.")
	}

	stateToken := q.Get("state")
	if stateToken == "" {
		oauthErr := trace.OAuth2("invalid_request", "missing state query param", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from OIDC provider.")
	}
	diagCtx.RequestID = stateToken

	req, err := s.a.Services.GetOIDCAuthRequest(ctx, stateToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC Auth Request.")
	}
	diagCtx.Info.TestFlow = req.SSOTestFlow

	connector, err := s.getOIDCConnector(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC connector.")
	}

	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	oauthConfig, err := s.newOAuth2Config(connector, redirectURL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Exchange code for token
	var exchangeOpts []oauth2.AuthCodeOption
	if req.PkceVerifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam("code_verifier", req.PkceVerifier))
	}

	token, err := oauthConfig.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to exchange OIDC auth code for token.")
	}

	logger.DebugContext(ctx, "Exchanged OIDC auth code for token", "token_type", token.TokenType)

	// Extract claims from the ID token and/or UserInfo endpoint
	claims, err := s.getClaims(ctx, connector, oauthConfig, token, logger)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC claims.")
	}

	logger.DebugContext(ctx, "Retrieved OIDC claims", "claims", claims)

	// Map claims to traits
	traits := oidcClaimsToTraits(claims)

	// Determine username
	username := s.getUsername(connector, claims)
	if username == "" {
		return nil, trace.BadParameter("could not determine username from OIDC claims, check username_claim setting on the connector")
	}

	// Map traits to roles
	_, roles := services.TraitsToRoles(connector.GetTraitMappings(), traits)
	if len(roles) == 0 {
		return nil, trace.AccessDenied("no roles mapped from OIDC claims for user %q, check claims_to_roles on the connector", username)
	}

	// Run login rules
	evaluationInput := &loginrule.EvaluationInput{
		Traits: traits,
	}
	evaluationOutput, err := s.a.GetLoginRuleEvaluator().Evaluate(ctx, evaluationInput)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	traits = evaluationOutput.Traits

	// Re-evaluate roles after login rules (traits may have changed)
	_, roles = services.TraitsToRoles(connector.GetTraitMappings(), traits)
	if len(roles) == 0 {
		return nil, trace.AccessDenied("no roles mapped from OIDC claims after login rules for user %q", username)
	}

	// Calculate session TTL
	fetchedRoles, err := services.FetchRoles(roles, s.a, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleTTL := fetchedRoles.AdjustSessionTTL(apidefaults.MaxCertDuration)
	sessionTTL := utils.MinTTL(roleTTL, req.CertTTL)

	// Determine a user ID from the "sub" claim
	userID := ""
	if sub, ok := claims["sub"]; ok {
		userID = fmt.Sprintf("%v", sub)
	}

	// Create or update the user
	expires := s.a.GetClock().Now().UTC().Add(sessionTTL)
	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      username,
			Namespace: apidefaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  roles,
			Traits: traits,
			OIDCIdentities: []types.ExternalIdentity{{
				ConnectorID: connector.GetName(),
				Username:    username,
				UserID:      userID,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: s.a.GetClock().Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.OIDC,
					ID:       connector.GetName(),
					Identity: username,
				},
			},
		},
	}

	dryRun := req.SSOTestFlow

	if !dryRun {
		existingUser, err := s.a.Services.GetUser(ctx, username, false)
		if err != nil && !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}

		if existingUser != nil {
			ref := user.GetCreatedBy().Connector
			if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
				return nil, trace.AlreadyExists("local user %q already exists and is not an OIDC user", existingUser.GetName())
			}
			user.SetRevision(existingUser.GetRevision())
			if _, err := s.a.UpdateUser(ctx, user); err != nil {
				return nil, trace.Wrap(err)
			}
		} else {
			if _, err := s.a.CreateUser(ctx, user); err != nil {
				return nil, trace.Wrap(err)
			}
		}
	}

	if err := s.a.CallLoginHooks(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}

	userState, err := s.a.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	oidcReq := authclient.OIDCAuthRequest{
		ConnectorID:       req.ConnectorID,
		CSRFToken:         req.CSRFToken,
		CreateWebSession:  req.CreateWebSession,
		ClientRedirectURL: req.ClientRedirectURL,
		SSHPubKey:         req.SshPublicKey,
		TLSPubKey:         req.TlsPublicKey,
	}

	// For test flow, skip session creation
	if req.SSOTestFlow {
		diagCtx.Info.Success = true
		return &authclient.OIDCAuthResponse{
			Identity: types.ExternalIdentity{
				ConnectorID: connector.GetName(),
				Username:    username,
				UserID:      userID,
			},
			Username: username,
			Req:      oidcReq,
		}, nil
	}

	// Build the auth response with session and certificates
	return s.makeOIDCAuthResponse(ctx, req, userState, connector.GetName(), username, userID, sessionTTL, oidcReq, logger)
}

func (s *AGPLOIDCService) makeOIDCAuthResponse(
	ctx context.Context,
	req *types.OIDCAuthRequest,
	userState services.UserState,
	connectorName, username, userID string,
	sessionTTL time.Duration,
	oidcReq authclient.OIDCAuthRequest,
	logger *slog.Logger,
) (*authclient.OIDCAuthResponse, error) {
	auth := authclient.OIDCAuthResponse{
		Identity: types.ExternalIdentity{
			ConnectorID: connectorName,
			Username:    username,
			UserID:      userID,
		},
		Username: userState.GetName(),
		Req:      oidcReq,
	}

	if req.CreateWebSession {
		session, err := s.a.CreateWebSessionFromReq(ctx, NewWebSessionRequest{
			User:                 userState.GetName(),
			Roles:                userState.GetRoles(),
			Traits:               userState.GetTraits(),
			SessionTTL:           sessionTTL,
			LoginTime:            s.a.clock.Now().UTC(),
			LoginIP:              req.ClientLoginIP,
			LoginUserAgent:       req.ClientUserAgent,
			AttestWebSession:     true,
			CreateDeviceWebToken: true,
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create web session.")
		}
		auth.Session = session
	}

	if len(req.SshPublicKey) != 0 || len(req.TlsPublicKey) != 0 {
		sshCert, tlsCert, err := s.a.CreateSessionCerts(ctx, &SessionCertsRequest{
			UserState:               userState,
			SessionTTL:              sessionTTL,
			SSHPubKey:               req.SshPublicKey,
			TLSPubKey:               req.TlsPublicKey,
			SSHAttestationStatement: hardwarekey.AttestationStatementFromProto(req.SshAttestationStatement),
			TLSAttestationStatement: hardwarekey.AttestationStatementFromProto(req.TlsAttestationStatement),
			Compatibility:           req.Compatibility,
			RouteToCluster:          req.RouteToCluster,
			KubernetesCluster:       req.KubernetesCluster,
			LoginIP:                 req.ClientLoginIP,
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create session certificate.")
		}

		clusterName, err := s.a.GetClusterName(ctx)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain cluster name.")
		}

		auth.Cert = sshCert
		auth.TLSCert = tlsCert

		authority, err := s.a.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain cluster's host CA.")
		}
		auth.HostSigners = append(auth.HostSigners, authority)
	}

	if o, err := s.a.ClientOptionsForLogin(userState); err == nil {
		auth.ClientOptions = o
	} else {
		logger.WarnContext(ctx, "Failed to calculate client options for OIDC login", "username", userState.GetName(), "error", err)
	}

	return &auth, nil
}

// getOIDCConnector loads the OIDC connector for the given request.
func (s *AGPLOIDCService) getOIDCConnector(ctx context.Context, req types.OIDCAuthRequest) (types.OIDCConnector, error) {
	if req.SSOTestFlow {
		if req.ConnectorSpec == nil {
			return nil, trace.BadParameter("ConnectorSpec is required for SSO test flow")
		}
		connector, err := types.NewOIDCConnector(req.ConnectorID, *req.ConnectorSpec)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return connector, nil
	}

	connector, err := s.a.GetOIDCConnector(ctx, req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}

// newOAuth2Config creates an OAuth2 config from the OIDC connector.
func (s *AGPLOIDCService) newOAuth2Config(connector types.OIDCConnector, redirectURL string) (*oauth2.Config, error) {
	issuerURL := connector.GetIssuerURL()

	// Try to discover endpoints from the OIDC provider
	authURL, tokenURL, err := s.discoverEndpoints(issuerURL)
	if err != nil {
		return nil, trace.Wrap(err, "failed to discover OIDC endpoints for issuer %q", issuerURL)
	}

	scopes := connector.GetScope()
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	return &oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}, nil
}

// oidcDiscoveryResponse is the well-known OpenID configuration response.
type oidcDiscoveryResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// discoverEndpoints fetches the OIDC discovery document from the issuer.
func (s *AGPLOIDCService) discoverEndpoints(issuerURL string) (authURL, tokenURL string, err error) {
	discoveryURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	resp, err := http.Get(discoveryURL)
	if err != nil {
		return "", "", trace.Wrap(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", trace.BadParameter("OIDC discovery failed for %q: %s %s", issuerURL, resp.Status, string(body))
	}

	var discovery oidcDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", "", trace.Wrap(err, "failed to decode OIDC discovery response")
	}

	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" {
		return "", "", trace.BadParameter("OIDC discovery for %q missing required endpoints", issuerURL)
	}

	return discovery.AuthorizationEndpoint, discovery.TokenEndpoint, nil
}

// getClaims extracts claims from the ID token and optionally from the UserInfo endpoint.
func (s *AGPLOIDCService) getClaims(ctx context.Context, connector types.OIDCConnector, config *oauth2.Config, token *oauth2.Token, logger *slog.Logger) (map[string]any, error) {
	claims := make(map[string]any)

	// Extract claims from the ID token (if present)
	rawIDToken, ok := token.Extra("id_token").(string)
	if ok && rawIDToken != "" {
		idTokenClaims, err := s.parseIDTokenClaims(rawIDToken)
		if err != nil {
			logger.WarnContext(ctx, "Failed to parse ID token claims, will try UserInfo", "error", err)
		} else {
			for k, v := range idTokenClaims {
				claims[k] = v
			}
		}
	}

	// Also fetch from UserInfo endpoint if available
	userInfoClaims, err := s.getUserInfo(ctx, connector, token)
	if err != nil {
		logger.DebugContext(ctx, "UserInfo request failed or not available", "error", err)
	} else {
		for k, v := range userInfoClaims {
			claims[k] = v
		}
	}

	if len(claims) == 0 {
		return nil, trace.BadParameter("no claims obtained from OIDC provider, check connector configuration")
	}

	return claims, nil
}

// parseIDTokenClaims extracts claims from a JWT ID token without full validation.
// We trust the token because it was received directly from the token endpoint over TLS.
func (s *AGPLOIDCService) parseIDTokenClaims(rawToken string) (map[string]any, error) {
	token, err := jose.ParseSigned(rawToken)
	if err != nil {
		return nil, trace.Wrap(err, "failed to parse ID token")
	}

	var claims map[string]any
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, trace.Wrap(err, "failed to extract claims from ID token")
	}

	return claims, nil
}

// getUserInfo fetches claims from the OIDC UserInfo endpoint.
func (s *AGPLOIDCService) getUserInfo(ctx context.Context, connector types.OIDCConnector, token *oauth2.Token) (map[string]any, error) {
	issuerURL := connector.GetIssuerURL()
	discoveryURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer resp.Body.Close()

	var discovery oidcDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, trace.Wrap(err)
	}

	if discovery.UserInfoEndpoint == "" {
		return nil, trace.NotFound("no UserInfo endpoint available")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", discovery.UserInfoEndpoint, nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	userInfoResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer userInfoResp.Body.Close()

	if userInfoResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(userInfoResp.Body)
		return nil, trace.BadParameter("UserInfo request failed: %s %s", userInfoResp.Status, string(body))
	}

	var claims map[string]any
	if err := json.NewDecoder(userInfoResp.Body).Decode(&claims); err != nil {
		return nil, trace.Wrap(err)
	}

	return claims, nil
}

// getUsername extracts the username from OIDC claims based on connector configuration.
func (s *AGPLOIDCService) getUsername(connector types.OIDCConnector, claims map[string]any) string {
	// Check custom username_claim first
	if uc := connector.GetUsernameClaim(); uc != "" {
		if val, ok := claims[uc]; ok {
			return fmt.Sprintf("%v", val)
		}
	}

	// Try standard claims in order of preference
	for _, claim := range []string{"email", "preferred_username", "name", "sub"} {
		if val, ok := claims[claim]; ok {
			str := fmt.Sprintf("%v", val)
			if str != "" {
				return str
			}
		}
	}

	return ""
}

// oidcClaimsToTraits converts OIDC claims (map[string]any) to Teleport traits (map[string][]string).
func oidcClaimsToTraits(claims map[string]any) map[string][]string {
	traits := make(map[string][]string)
	for claimName, v := range claims {
		switch claimValue := v.(type) {
		case string:
			traits[claimName] = []string{claimValue}
		case []string:
			traits[claimName] = claimValue
		case []any:
			var vals []string
			for _, vv := range claimValue {
				vals = append(vals, fmt.Sprintf("%v", vv))
			}
			traits[claimName] = vals
		case float64:
			traits[claimName] = []string{fmt.Sprintf("%v", claimValue)}
		case bool:
			traits[claimName] = []string{fmt.Sprintf("%v", claimValue)}
		}
	}
	return traits
}
