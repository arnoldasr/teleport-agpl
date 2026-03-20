/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
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

package services

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	scopedaccessv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/scopes/access/v1"
	scopesv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/scopes/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/api/utils/keys"
	dtauthz "github.com/gravitational/teleport/lib/devicetrust/authz"
	"github.com/gravitational/teleport/lib/itertools/stream"
	"github.com/gravitational/teleport/lib/scopes"
	scopedaccess "github.com/gravitational/teleport/lib/scopes/access"
	"github.com/gravitational/teleport/lib/scopes/pinning"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/utils/once"
)

// ErrScopedIdentity is returned when a component intended for use only with unscoped identities receives a scoped
// identity. Methods that implement scoping support may check for this error and fallback to scoped authorization
// as appropriate.
var ErrScopedIdentity = &trace.AccessDeniedError{
	Message: "scoped identities not supported",
}

// checkAccessToRulesImpl verifies that *all* of a series of verbs are permitted for the specified resource. This
// function differs from AccessChecker.CheckAccessToRule in that it does not support advanced context-based features
// or namespacing, and accepts a set of verbs all of which must evaluate to allow for the check to succeed.
func checkAccessToRulesImpl(checker AccessChecker, ctx RuleContext, resource string, verbs ...string) error {
	if len(verbs) == 0 {
		return trace.BadParameter("malformed rule check for %q, no verbs provided (this is a bug)", resource)
	}
	for _, verb := range verbs {
		if err := checker.CheckAccessToRule(ctx, apidefaults.Namespace, resource, verb); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// checkMaybeHasAccessToRulesImpl returns an error if the checker definitely does not have access to the provided rules.
func checkMaybeHasAccessToRulesImpl(checker AccessChecker, ctx RuleContext, resource string, verbs ...string) error {
	if len(verbs) == 0 {
		return trace.BadParameter("malformed maybe has access to rule check for %q, no verbs provided (this is a bug)", resource)
	}
	for _, verb := range verbs {
		if err := checker.GuessIfAccessIsPossible(ctx, apidefaults.Namespace, resource, verb); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// ── ScopedAccessCheckerContext ───────────────────────────────────────────────

// roleCheckerKey identifies a unique single-role checker configuration by the combination of
// scope of origin, scope of effect, and role name.
type roleCheckerKey struct {
	scopeOfOrigin string
	scopeOfEffect string
	roleName      string
}

// defaultImplicitRoleKey is a sentinel key used to identify the default implicit role checker in caches.
var defaultImplicitRoleKey = roleCheckerKey{}

// ScopedAccessCheckerContext is the top-level access checker state, abstracting over scoped and unscoped
// identities. For scoped identities it builds and caches per-role checkers based on the user's scope pin
// and role assignments. For unscoped identities it wraps a standard AccessChecker.
type ScopedAccessCheckerContext struct {
	// scoped path — populated when isScoped()
	builder              scopedAccessCheckerBuilder
	cachedCheckerForRole func(ctx context.Context, key roleCheckerKey) (*ScopedAccessChecker, error)

	// unscoped path — populated when !isScoped()
	unscopedChecker AccessChecker
}

// NewScopedAccessCheckerContext builds a ScopedAccessCheckerContext for a scoped identity. The supplied
// context.Context is captured for propagating cancellation during role loading.
func NewScopedAccessCheckerContext(ctx context.Context, info *AccessInfo, localCluster string, reader ScopedRoleReader) (*ScopedAccessCheckerContext, error) {
	builder := scopedAccessCheckerBuilder{
		info:         info,
		localCluster: localCluster,
		reader:       reader,
	}

	if err := builder.Check(); err != nil {
		return nil, trace.Wrap(err)
	}

	cachedCheckerForRole, _ := once.KeyedValue(builder.newCheckerForRole)

	return &ScopedAccessCheckerContext{
		builder:              builder,
		cachedCheckerForRole: cachedCheckerForRole,
	}, nil
}

// NewScopedAccessCheckerContextFromUnscoped builds a ScopedAccessCheckerContext wrapping an unscoped AccessChecker.
func NewScopedAccessCheckerContextFromUnscoped(checker AccessChecker) *ScopedAccessCheckerContext {
	return &ScopedAccessCheckerContext{unscopedChecker: checker}
}

// isScoped reports whether this context operates on a scoped identity.
func (c *ScopedAccessCheckerContext) isScoped() bool {
	return c.unscopedChecker == nil
}

// ScopePin returns the scope pin for the identity, if the identity is scoped.
func (c *ScopedAccessCheckerContext) ScopePin() (*scopesv1.Pin, bool) {
	if !c.isScoped() {
		return nil, false
	}
	return c.builder.info.ScopePin, true
}

// CheckersForResourceScope returns a stream of ScopedAccessCheckers in evaluation order for the given resource
// scope. For scoped identities, this enforces pin compliance and yields per-role checkers ordered by scope of
// origin (ancestral to descendant) then scope of effect (descendant to ancestral). For unscoped identities,
// yields a single checker wrapping the full unscoped context.
//
// This is the mechanism that *must* be used for getting checkers when checking access to a resource.
func (c *ScopedAccessCheckerContext) CheckersForResourceScope(ctx context.Context, scope string) stream.Stream[*ScopedAccessChecker] {
	if !c.isScoped() {
		return func(yield func(*ScopedAccessChecker, error) bool) {
			yield(NewScopedAccessCheckerFromUnscoped(c.unscopedChecker), nil)
		}
	}
	return c.checkersForResourceScope(ctx, scope, true /* enforce pin */)
}

// RiskyUnpinnedCheckersForResourceScope is equivalent to CheckersForResourceScope except that it bypasses
// enforcement of the pinning scope. This is a risky operation that should only be used for certain APIs that
// make an exception to pinning exclusion rules (e.g. allowing read operations for resources at a parent scope).
func (c *ScopedAccessCheckerContext) RiskyUnpinnedCheckersForResourceScope(ctx context.Context, scope string) stream.Stream[*ScopedAccessChecker] {
	if !c.isScoped() {
		return func(yield func(*ScopedAccessChecker, error) bool) {
			yield(NewScopedAccessCheckerFromUnscoped(c.unscopedChecker), nil)
		}
	}
	return c.checkersForResourceScope(ctx, scope, false /* enforce pin */)
}

func (c *ScopedAccessCheckerContext) checkersForResourceScope(ctx context.Context, scope string, enforcePin bool) stream.Stream[*ScopedAccessChecker] {
	return func(yield func(*ScopedAccessChecker, error) bool) {
		// deny immediately if the resource scope is not subject to the pinned scope. note that this denial isn't just an
		// optimization, we have to perform this check separately from whatever access checks are performed by particular
		// checkers. This is vital as the pin scope itself may deny access to a resource that would be permitted by any
		// particular role. For example, if a user has a scoped role assigned at /foo which grants access to all ssh
		// nodes, but they are pinned to scope /foo/bar, even if a role at /foo permits access, the pin restricts
		// access to only resources subject to /foo/bar.
		if enforcePin && !pinning.PinAppliesToResourceScope(c.builder.info.ScopePin, scope) {
			yield(nil, trace.AccessDenied("scope pin %q does not apply to resource scope %q", c.builder.info.ScopePin.GetScope(), scope))
			return
		}

		var successfullyResolved int
		var lastErr error

		defaultImplicitChecker, err := c.cachedCheckerForRole(ctx, defaultImplicitRoleKey)
		if err != nil {
			slog.WarnContext(ctx, "skipping default implicit role evaluation due to error", "error", err)
			lastErr = err
		} else {
			// yield the default implicit role checker first. This simulates the presence of the default implicit
			// role at root scope, ensuring that its privileges are always considered first in evaluation.
			if !yield(defaultImplicitChecker, nil) {
				return
			}
			// note that we are not incrementing successfullyResolved here. the default implicit role doesn't
			// really count from the perspective of deciding whether or not we're hitting a systemic failure.
		}

		// iterate through the ordered enforcement points for this resource scope. policy evaluation by scope is ordered first by
		// Scope of Origin (ancestral to descendant) and then by Scope of Effect (descendant to ancestral within each origin).
		// We proceed through each permutation in order, evaluating any roles assigned at that specific point.
		for point := range scopes.EnforcementPointsForResourceScope(scope) {
			for roleName := range pinning.GetRolesAtEnforcementPoint(c.builder.info.ScopePin, point) {
				key := roleCheckerKey{
					scopeOfOrigin: point.ScopeOfOrigin,
					scopeOfEffect: point.ScopeOfEffect,
					roleName:      roleName,
				}
				checker, err := c.cachedCheckerForRole(ctx, key)
				if err != nil {
					// in classic teleport access checking skipping a role would be unacceptable due to side effects and deny rules. the scoped model
					// however relies on cross-role isolation and explicitly allows omission of roles.
					slog.WarnContext(ctx, "skipping role evaluation due to error", "role_name", roleName, "scope_of_origin", point.ScopeOfOrigin, "scope_of_effect", point.ScopeOfEffect, "error", err)
					lastErr = err
					continue
				}
				if !yield(checker, nil) {
					return
				}
				successfullyResolved++
			}
		}

		if successfullyResolved == 0 && lastErr != nil {
			// if we didn't successfully build any assignment-derived checkers and encountered errors, return the last error encountered
			// as it may be indicative of some kind of systemic failure rather than a problem with a specific assignment.
			yield(nil, lastErr)
		}
	}
}

// riskyEnumerateScopedCheckers returns a stream of all possible scoped access checkers for the identity,
// enumerating every role assignment in the pin's assignment tree. The order is undefined and must not be
// relied upon for access control decisions. This method panics if called on an unscoped context — it is
// only meaningful for scoped identities.
//
// Note that use of this method should be treated with extreme caution. Accidental misuse could easily
// result in a scope isolation violation.
func (c *ScopedAccessCheckerContext) riskyEnumerateScopedCheckers(ctx context.Context) stream.Stream[*ScopedAccessChecker] {
	if !c.isScoped() {
		panic("riskyEnumerateScopedCheckers called on an unscoped access checker context (this is a bug)")
	}
	return func(yield func(*ScopedAccessChecker, error) bool) {
		var yielded int
		var lastErr error
		for assignment := range pinning.EnumerateAllAssignments(c.builder.info.ScopePin) {
			key := roleCheckerKey{
				scopeOfOrigin: assignment.ScopeOfOrigin,
				scopeOfEffect: assignment.ScopeOfEffect,
				roleName:      assignment.RoleName,
			}
			checker, err := c.cachedCheckerForRole(ctx, key)
			if err != nil {
				slog.WarnContext(ctx, "skipping role evaluation due to error", "role_name", assignment.RoleName, "scope_of_origin", assignment.ScopeOfOrigin, "scope_of_effect", assignment.ScopeOfEffect, "error", err)
				continue
			}
			if !yield(checker, nil) {
				return
			}
			yielded++
		}
		if yielded == 0 && lastErr != nil {
			yield(nil, lastErr)
		}
	}
}

// CheckMaybeHasAccessToRules returns an error if the context definitely does not have access to the provided
// rules. For scoped identities, always returns nil — the scoped access model evaluates permissions per-resource.
func (c *ScopedAccessCheckerContext) CheckMaybeHasAccessToRules(ctx RuleContext, resource string, verbs ...string) error {
	if !c.isScoped() {
		return checkMaybeHasAccessToRulesImpl(c.unscopedChecker, ctx, resource, verbs...)
	}
	return nil
}

// Decision calls fn against each checker in the resource scope evaluation order until one of three
// conditions is met: (1) fn succeeds, (2) fn returns an explicitly denied error, or (3) all checkers
// have been exhausted (implicit deny).
func (c *ScopedAccessCheckerContext) Decision(ctx context.Context, scope string, fn func(*ScopedAccessChecker) error) error {
	return c.decision(ctx, c.CheckersForResourceScope(ctx, scope), fn)
}

// RiskyUnpinnedDecision is equivalent to Decision except that it bypasses enforcement of the pinning scope.
func (c *ScopedAccessCheckerContext) RiskyUnpinnedDecision(ctx context.Context, scope string, fn func(*ScopedAccessChecker) error) error {
	return c.decision(ctx, c.RiskyUnpinnedCheckersForResourceScope(ctx, scope), fn)
}

func (c *ScopedAccessCheckerContext) decision(ctx context.Context, checkers stream.Stream[*ScopedAccessChecker], fn func(*ScopedAccessChecker) error) error {
	for checker, err := range checkers {
		if err != nil {
			return trace.Wrap(err)
		}
		err = fn(checker)
		switch {
		case err == nil:
			return nil
		case IsAccessExplicitlyDenied(err):
			return trace.Wrap(err)
		default:
			// implicit deny, continue to the next check
			continue
		}
	}
	return trace.AccessDenied("access denied (decision)")
}

// AccessStateFromSSHIdentity builds an AccessState from an SSH identity, abstracting over scoped and
// unscoped access state construction.
func (c *ScopedAccessCheckerContext) AccessStateFromSSHIdentity(ctx context.Context, ident *sshca.Identity, authPrefGetter AuthPreferenceGetter) (AccessState, error) {
	if !c.isScoped() {
		return AccessStateFromSSHIdentity(ctx, ident, c.unscopedChecker, authPrefGetter)
	}

	authPref, err := authPrefGetter.GetAuthPreference(ctx)
	if err != nil {
		return AccessState{}, trace.Wrap(err)
	}

	if authPref.GetRequireMFAType().IsSessionMFARequired() {
		// TODO(fspmarshall/scopes): implement scoped MFA
		// NOTE: this will require additional refactoring of relevant access-checking logic. currently, we often
		// check MFA requirements *before* we determine access to the underlying resource, but a scoped MFA model
		// will need to first determine the scope of access *before* we can determine whether MFA is required for that scope.
		return AccessState{}, trace.AccessDenied("cannot perform scoped access when cluster-level MFA is required (scoped MFA is not implemented)")
	}

	return AccessState{
		// MFA state is hard-coded here because scoped roles do not support MFA yet, and the above check should reject
		// cases where cluster-level config would obligate MFA.
		MFARequired:              MFARequiredNever,
		MFAVerified:              false,
		EnableDeviceVerification: true,
		DeviceVerified:           dtauthz.IsSSHDeviceVerified(ident),
		IsBot:                    ident.IsBot(),
	}, nil
}

// Traits returns the user traits for this context.
func (c *ScopedAccessCheckerContext) Traits() wrappers.Traits {
	if !c.isScoped() {
		return c.unscopedChecker.Traits()
	}
	return c.builder.info.Traits
}

// CertParams returns a sub-context for resolving certificate parameters during certificate generation.
// This should not be used outside of certificate generation logic.
func (c *ScopedAccessCheckerContext) CertParams() *CertificateParameterContext {
	return &CertificateParameterContext{ctx: c}
}

// ── scopedAccessCheckerBuilder ───────────────────────────────────────────────

// scopedAccessCheckerBuilder is a helper that builds scoped access checkers.
type scopedAccessCheckerBuilder struct {
	info         *AccessInfo
	localCluster string
	reader       ScopedRoleReader
}

// Check verifies that the builder was provided with all necessary parameters and that they are well-formed.
func (b *scopedAccessCheckerBuilder) Check() error {
	if b.reader == nil {
		return trace.BadParameter("cannot create scoped access checkers without a scoped role reader")
	}
	if b.localCluster == "" {
		return trace.BadParameter("cannot create scoped access checkers without a local cluster name")
	}
	if b.info.ScopePin == nil {
		return trace.BadParameter("cannot create scoped access checkers for unscoped identity")
	}
	if len(b.info.AllowedResourceAccessIDs) != 0 {
		return trace.BadParameter("cannot create scoped access checkers for identity with active resource IDs")
	}
	if err := pinning.WeakValidate(b.info.ScopePin); err != nil {
		return trace.Errorf("cannot create scoped access checkers: %w", err)
	}
	return nil
}

func (b *scopedAccessCheckerBuilder) newCheckerForRole(ctx context.Context, key roleCheckerKey) (*ScopedAccessChecker, error) {
	if key == defaultImplicitRoleKey {
		return b.newDefaultImplicitChecker(ctx), nil
	}

	rsp, err := b.reader.GetScopedRole(ctx, &scopedaccessv1.GetScopedRoleRequest{
		Name: key.roleName,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// ensure that the role's resource scope makes it assignable from the scope of origin
	if !scopedaccess.RoleIsAssignableFromScopeOfOrigin(rsp.Role, key.scopeOfOrigin) {
		return nil, trace.BadParameter("scoped role %q is not assignable from scope of origin %q", key.roleName, key.scopeOfOrigin)
	}

	// ensure the role's configuration makes it assignable at the scope of effect
	if !scopedaccess.RoleIsAssignableToScopeOfEffect(rsp.Role, key.scopeOfEffect) {
		return nil, trace.BadParameter("scoped role %q is not assignable to scope of effect %q", key.roleName, key.scopeOfEffect)
	}

	// Convert the scoped role to a classic role using the scope of effect.
	// The scope of effect determines which resources this role's privileges apply to.
	role, err := scopedaccess.ScopedRoleToRole(rsp.Role, key.scopeOfEffect)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO(fspmarshall/scopes): figure out how/when we want to support trait interpolation in scoped
	// roles. When we do, that will likely need to be done here.

	// Create an access checker with this single role. Single-role evaluation is a core principle
	// of the scoped access model - the first role that permits access determines all parameters.
	checker := newAccessChecker(b.info, b.localCluster, NewRoleSet(role))

	return &ScopedAccessChecker{
		scopeOfOrigin:       key.scopeOfOrigin,
		scopeOfEffect:       key.scopeOfEffect,
		role:                rsp.Role,
		scopedCompatChecker: checker,
	}, nil
}

// newDefaultImplicitChecker builds a scoped access checker representing the default implicit role. We rely on the privileges conferred
// by the default implicit role always being "assigned" at root as if they came from a root scoped role assignment. We achieve this by
// creating a fake scoped access checker that wraps an "empty" unscoped access checker. Since all unscoped access checkers automatically
// include the default implicit role, this effectively simulates the presence of the default implicit role at root scope. Note that as
// functionality of scoped roles further diverges from unscoped roles, we may need to revisit this approach in favor of defining our
// own default implicit scoped role instead.
func (b *scopedAccessCheckerBuilder) newDefaultImplicitChecker(_ context.Context) *ScopedAccessChecker {
	return &ScopedAccessChecker{
		scopeOfOrigin:       scopes.Root,
		scopeOfEffect:       scopes.Root,
		scopedCompatChecker: newAccessChecker(b.info, b.localCluster, NewRoleSet()), // default implicit role definition is auto-populated by NewRoleSet()
		role: &scopedaccessv1.ScopedRole{
			Metadata: &headerv1.Metadata{
				Name: constants.DefaultImplicitRole,
			},
			Scope: scopes.Root,
			Spec: &scopedaccessv1.ScopedRoleSpec{
				AssignableScopes: []string{scopes.Root},
			},
			Version: types.V1,
		},
	}
}

// ── ScopedAccessChecker ──────────────────────────────────────────────────────

// ScopedAccessChecker performs access checks abstracting over scoped and unscoped identities.
//
// For scoped identities, each ScopedAccessChecker represents a single role assignment characterized by:
//   - Scope of Origin: the scope from which the assignment originates (determines seniority)
//   - Scope of Effect: the scope at which the role's privileges apply (determines applicability)
//
// In the scoped access model, the first role (in evaluation order) that permits access to a resource
// determines all subsequent access parameters. This differs from classic role evaluation where roles are
// aggregated and the most restrictive settings win.
//
// For unscoped identities, the full AccessChecker is wrapped directly and all method calls are delegated to it.
//
// ScopedAccessChecker instances should be obtained from ScopedAccessCheckerContext rather than constructed
// directly. The exception is NewScopedAccessCheckerFromUnscoped for adapting an unscoped AccessChecker.
type ScopedAccessChecker struct {
	// scopeOfOrigin/scopeOfEffect are populated only for scoped identities; zero for unscoped.
	scopeOfOrigin string
	scopeOfEffect string

	// role is the scoped role being evaluated, or nil for unscoped identities.
	role *scopedaccessv1.ScopedRole

	// scopedCompatChecker is a classic AccessChecker built from the scoped role via ScopedRoleToRole.
	// Non-nil iff isScoped(). Used for checks that fall back to compat classic-role logic.
	scopedCompatChecker AccessChecker

	// unscopedChecker is the underlying unscoped AccessChecker.
	// Non-nil iff !isScoped().
	unscopedChecker AccessChecker
}

// NewScopedAccessCheckerFromUnscoped creates a ScopedAccessChecker wrapping an unscoped AccessChecker.
// This is used in code paths that accept *ScopedAccessChecker but operate on an unscoped identity.
func NewScopedAccessCheckerFromUnscoped(checker AccessChecker) *ScopedAccessChecker {
	return &ScopedAccessChecker{unscopedChecker: checker}
}

// isScoped reports whether this checker operates on a scoped identity.
func (c *ScopedAccessChecker) isScoped() bool {
	return c.role != nil
}

// SSH returns an SSH-specific access checker backed by this checker. All SSH-specific methods
// (logins, port forwarding, recording mode, idle timeout, etc.) live on [SSHAccessChecker].
func (c *ScopedAccessChecker) SSH() *SSHAccessChecker {
	return &SSHAccessChecker{checker: c}
}

// ScopeOfOrigin returns the scope from which this role assignment originates. Roles assigned from
// more ancestral scopes take precedence over roles assigned from more descendant scopes.
func (c *ScopedAccessChecker) ScopeOfOrigin() string {
	return c.scopeOfOrigin
}

// ScopeOfEffect returns the scope at which this role's privileges apply. Within a given scope of
// origin, roles with more descendant/specific scopes of effect take precedence.
func (c *ScopedAccessChecker) ScopeOfEffect() string {
	return c.scopeOfEffect
}

// RoleName returns the name of the role being evaluated by this checker.
func (c *ScopedAccessChecker) RoleName() string {
	return c.role.GetMetadata().GetName()
}

// ScopePin returns the scope pin this checker was created from.
func (c *ScopedAccessChecker) ScopePin() *scopesv1.Pin {
	return c.AccessInfo().ScopePin
}

// AccessInfo returns the AccessInfo that this access checker is based on.
func (c *ScopedAccessChecker) AccessInfo() *AccessInfo {
	if !c.isScoped() {
		return c.unscopedChecker.AccessInfo()
	}
	return c.scopedCompatChecker.AccessInfo()
}

// Traits returns the set of user traits.
func (c *ScopedAccessChecker) Traits() wrappers.Traits {
	// there is no concept of scoped traits currently, and none is planned or would be feasible at least
	// until we've fully migrated to PDP and deprecated certificate-based traits.
	if !c.isScoped() {
		return c.unscopedChecker.Traits()
	}
	return c.scopedCompatChecker.Traits()
}

// CheckAccessToRules verifies that *all* of a series of verbs are permitted for the specified resource.
func (c *ScopedAccessChecker) CheckAccessToRules(ctx RuleContext, resource string, verbs ...string) error {
	if !c.isScoped() {
		return checkAccessToRulesImpl(c.unscopedChecker, ctx, resource, verbs...)
	}
	return checkAccessToRulesImpl(c.scopedCompatChecker, ctx, resource, verbs...)
}

// CheckAccessToRemoteCluster checks access to a remote cluster.
func (c *ScopedAccessChecker) CheckAccessToRemoteCluster(cluster types.RemoteCluster) error {
	if !c.isScoped() {
		return c.unscopedChecker.CheckAccessToRemoteCluster(cluster)
	}
	// remote cluster access is never permitted for scoped identities.
	// NOTE: it is unclear whether or not this method should even be implemented for the scoped access checker. it may be more
	// sensible to force outer enforcement logic to grapple with the fact that a scoped checker does not support remote clusters
	// at the type-level. this has been implemented experimentally to explore the pattern of having the scoped access checker
	// implement methods that always deny for unsupported features.
	return trace.AccessDenied("remote cluster access is not permitted for scoped identities")
}

// AdjustSessionTTL will reduce the requested ttl to the lowest max allowed TTL for this role set.
func (c *ScopedAccessChecker) AdjustSessionTTL(ttl time.Duration) time.Duration {
	// the naive implementation of this method for scopes may have problematic interactions with
	// cert parameter generation. see ../scopes/access/compat.go for more detailed discussion.
	if !c.isScoped() {
		return c.unscopedChecker.AdjustSessionTTL(ttl)
	}
	return c.scopedCompatChecker.AdjustSessionTTL(ttl)
}

// PrivateKeyPolicy returns the enforced private key policy, or the provided default, whichever is stricter.
func (c *ScopedAccessChecker) PrivateKeyPolicy(defaultPolicy keys.PrivateKeyPolicy) (keys.PrivateKeyPolicy, error) {
	// the naive implementation of this method for scopes may have problematic interactions with
	// cert parameter generation. see ../scopes/access/compat.go for more detailed discussion.
	if !c.isScoped() {
		return c.unscopedChecker.PrivateKeyPolicy(defaultPolicy)
	}
	return c.scopedCompatChecker.PrivateKeyPolicy(defaultPolicy)
}

// PinSourceIP returns whether source IP pinning is enforced.
func (c *ScopedAccessChecker) PinSourceIP() bool {
	// the naive implementation of this method for scopes may have problematic interactions with
	// cert parameter generation. see ../scopes/access/compat.go for more detailed discussion.
	if !c.isScoped() {
		return c.unscopedChecker.PinSourceIP()
	}
	return c.scopedCompatChecker.PinSourceIP()
}

// LockingMode returns the locking mode to apply.
func (c *ScopedAccessChecker) LockingMode(defaultMode constants.LockingMode) constants.LockingMode {
	// the naive implementation of this method for scopes may have problematic interactions with
	// cert parameter generation. see ../scopes/access/compat.go for more detailed discussion.
	if !c.isScoped() {
		return c.unscopedChecker.LockingMode(defaultMode)
	}
	return c.scopedCompatChecker.LockingMode(defaultMode)
}

// ── Certificate Parameters ───────────────────────────────────────────────────

// UnscopedCertificateParameters represents a subset of the AccessChecker interface that
// is used during certificate generation to obtain certificate parameters that are only
// meaningful for unscoped identities.
type UnscopedCertificateParameters interface {
	RoleNames() []string
	CertificateFormat() string
	CertificateExtensions() []*types.CertExtension
	CheckKubeGroupsAndUsers(ttl time.Duration, overrideTTL bool, matchers ...RoleMatcher) ([]string, []string, error)
	CheckDatabaseNamesAndUsers(ttl time.Duration, overrideTTL bool) ([]string, []string, error)
	CheckAWSRoleARNs(ttl time.Duration, overrideTTL bool) ([]string, error)
	CheckAzureIdentities(ttl time.Duration, overrideTTL bool) ([]string, error)
	CheckGCPServiceAccounts(ttl time.Duration, overrideTTL bool) ([]string, error)
	GetAllowedResourceAccessIDs() []types.ResourceAccessID
	CheckAccessToRemoteCluster(rc types.RemoteCluster) error
}

// CertificateParameterContext provides methods for resolving certificate parameters that abstract
// over scoped and unscoped identities. Methods on this type should only be called during certificate
// generation and return parameters that need to be embedded in the certificate at issuance time. For
// unscoped identities these parameters are generally equivalent to those returned by the underlying
// AccessChecker. For scoped identities things get more complex as most certificate parameters cannot
// be determined by scoped roles. Instead, parameters for scoped identities are generally hard-coded for
// the time being, with the intent to revisit them in the future and to provide non-role means of
// configuring them. See the Scopes RFD for more details on how scoped permissions intersect with
// certificate parameters.
type CertificateParameterContext struct {
	ctx *ScopedAccessCheckerContext
}

// UnscopedCertParams returns unscoped-specific certificate parameters if this is an unscoped
// identity, or nil if this is a scoped identity. Use this for certificate parameters
// that are only meaningful for unscoped identities (e.g., kube groups, db users).
func (n *CertificateParameterContext) UnscopedCertParams() UnscopedCertificateParameters {
	return n.ctx.unscopedChecker
}

// GetSSHLoginsForTTL verifies that the requested session TTL is valid and returns
// the list of allowed logins for the certificate.
//   - Unscoped: Returns logins from roles, restricted by role TTL rules
//   - Scoped: Returns all possible logins across all roles in the pin. this behavior is necessary
//     because we cannot determine the effective role without knowing the target resource, but the ssh
//     protocol requires all valid principals to be present in the certificate at issuance time. Subsequent
//     access checks will enforce login restrictions based on the effective role once the target resource
//     is known. Note that this function is *not* safe to determine the logins to be used for OpenSSH agent
//     access certs.
func (n *CertificateParameterContext) GetSSHLoginsForTTL(ctx context.Context, ttl time.Duration) ([]string, error) {
	if !n.ctx.isScoped() {
		return n.ctx.unscopedChecker.CheckLoginDuration(ttl)
	}

	// For scoped identities, enumerate all possible logins across all roles in the pin.
	// We cannot restrict logins based on a single role since we don't know which role will
	// grant access without knowing the target resource.
	loginSet := make(map[string]struct{})

	// Use of riskyEnumerateScopedCheckers is acceptable here because we are deliberately attempting to aggregate
	// information across all roles, rather than making a specific access-control decision.
	for checker, err := range n.ctx.riskyEnumerateScopedCheckers(ctx) {
		if err != nil {
			return nil, trace.Wrap(err)
		}

		// Get logins from this checker. Pass 0 as TTL to get all logins without TTL restriction.
		// We're not enforcing per-role TTL restrictions for scoped certs since the effective role
		// is unknown at cert generation time.
		for _, login := range checker.SSH().getScopedLogins() {
			// Skip placeholder logins when aggregating across roles
			if !strings.HasPrefix(login, constants.NoLoginPrefix) {
				loginSet[login] = struct{}{}
			}
		}
	}

	// Convert map to sorted slice for deterministic output
	logins := make([]string, 0, len(loginSet))
	for login := range loginSet {
		logins = append(logins, login)
	}
	slices.Sort(logins)

	if len(logins) == 0 {
		// User was deliberately configured to have no login capability,
		// but SSH certificates must contain at least one valid principal.
		// We add a single distinctive value which should be unique, and
		// will never be a valid unix login (due to leading '-').
		logins = []string{constants.NoLoginPrefix + uuid.New().String()}
	}

	return logins, nil
}

// AdjustSessionTTL adjusts the requested session TTL based on role/configuration policies.
func (n *CertificateParameterContext) AdjustSessionTTL(ttl time.Duration) time.Duration {
	if !n.ctx.isScoped() {
		return n.ctx.unscopedChecker.AdjustSessionTTL(ttl)
	}
	// Scoped identities: return the requested TTL unchanged. We cannot restrict TTL based on roles
	// since we don't know which role will grant access without knowing the target resource.
	// TODO(fspmarshall/scopes): determine how to handle session TTL restrictions for scoped identities. This will
	// likely involve fully decoupling session TTL and certificate TTL, since scoped cert TTLs will need to
	// be determined by non-role configuration, whereas specific resource access sessions may still be able to
	// be controlled by roles.
	return ttl
}

// PrivateKeyPolicy returns the private key policy to enforce for the certificate.
func (n *CertificateParameterContext) PrivateKeyPolicy(defaultPolicy keys.PrivateKeyPolicy) (keys.PrivateKeyPolicy, error) {
	if !n.ctx.isScoped() {
		return n.ctx.unscopedChecker.PrivateKeyPolicy(defaultPolicy)
	}
	// Scoped roles do not currently support custom private key policies. Return the cluster default.
	// TODO(fspmarshall/scopes): determine what (if any) control should permit setting the private key
	// policy for scoped certificates.
	return defaultPolicy, nil
}

// PinSourceIP returns whether source IP pinning should be enabled in the certificate.
func (n *CertificateParameterContext) PinSourceIP() bool {
	if !n.ctx.isScoped() {
		return n.ctx.unscopedChecker.PinSourceIP()
	}
	// Scoped identities do not support source IP pinning due to scope isolation concerns.
	// TODO(fspmarshall/scopes): determine what (if any) control should permit setting the source IP
	// pinning for scoped certificates. Likely this will need to be a cluster configuration rather than
	// a role-based setting.
	return false
}

// CanPortForward returns whether port forwarding should be permitted in the certificate.
func (n *CertificateParameterContext) CanPortForward() bool {
	if !n.ctx.isScoped() {
		return n.ctx.unscopedChecker.CanPortForward()
	}
	// Scoped identities: use unstable env var configuration
	// TODO(fspmarshall/scopes): determine what (if any) control should permit setting the port forwarding
	// permission for scoped certificates.
	return scopedaccess.UnstableGetScopedPortForwarding()
}

// CanForwardAgents returns whether agent forwarding should be permitted in the certificate.
func (n *CertificateParameterContext) CanForwardAgents() bool {
	if !n.ctx.isScoped() {
		return n.ctx.unscopedChecker.CanForwardAgents()
	}
	// Scoped identities: use unstable env var configuration
	// TODO(fspmarshall/scopes): determine what (if any) control should permit setting the agent forwarding
	// extension for scoped certificates.
	return scopedaccess.UnstableGetScopedForwardAgent()
}

// PermitX11Forwarding returns whether X11 forwarding should be permitted in the certificate.
func (n *CertificateParameterContext) PermitX11Forwarding() bool {
	if !n.ctx.isScoped() {
		return n.ctx.unscopedChecker.PermitX11Forwarding()
	}
	// Scoped identities: hard-coded to false (no unstable env var for X11 forwarding)
	// TODO(fspmarshall/scopes): determine what (if any) control should permit setting the X11 forwarding
	// permission for scoped certificates.
	return false
}

// LockingMode returns the locking mode to apply for the certificate.
func (n *CertificateParameterContext) LockingMode(defaultMode constants.LockingMode) constants.LockingMode {
	if !n.ctx.isScoped() {
		return n.ctx.unscopedChecker.LockingMode(defaultMode)
	}
	// Scoped roles do not currently support custom locking modes. Return the default/cluster mode.
	// TODO(fspmarshall/scopes): determine how to handle locking mode for scoped certificates given that
	// role-affected locking behavior during certificate creation doesn't map well to pinned certificates.
	return defaultMode
}
