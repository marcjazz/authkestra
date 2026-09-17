//! Re-proof gating: requiring a *fresh* authentication before an operation
//! that changes an account's security posture.
//!
//! ## The exposure this closes
//!
//! Enrolling a second factor is not an ordinary authenticated action. If
//! someone holds a session they should not — a stolen cookie, XSS, an
//! unlocked laptop — and the enrolment endpoint asks only for a live
//! session, they can enrol *their own* TOTP secret or passkey against the
//! victim's account. They then hold a factor the real owner does not know
//! about, and the account ends up more firmly theirs than the owner's. The
//! same reasoning covers re-issuing recovery codes, changing a recovery
//! address, and disabling a factor.
//!
//! ## Why this is method-agnostic
//!
//! The usual fix is to demand the account password (better-auth's
//! `twoFactor.enable({ password })`, for instance). Authkestra structurally
//! cannot offer that: there is no first-party end-user password concept —
//! [`BasicAuthenticator`](crate::auth::strategy::BasicAuthenticator)
//! delegates validation to the application, and the `argon2` usage in this
//! crate hashes OAuth *client* secrets — and per decision 0005 the framework
//! owns no user table.
//!
//! That constraint points at the better answer anyway. A gate that demands
//! one named factor is wrong for an account that does not have it: a
//! social-login-only or passwordless account has no password to re-enter.
//! So this gate asks a question every account can answer — *how recently,
//! and how strongly, did this identity prove itself?* — and leaves "with
//! what" to whatever the account actually has.
//!
//! It reads the two attributes
//! [`Engine::authenticate`](crate::Engine::authenticate) already stamps:
//! [`IDENTITY_ATTR_AUTH_TIME`] for the *when*, and
//! [`IDENTITY_ATTR_STEP_UP_SATISFIED`] for the *how strongly*. Nothing new
//! has to be recorded, and no new store is involved.
//!
//! ## Signal, don't perform
//!
//! [`ReproofRequirement::check`] returns a verdict; it never runs a login.
//! This is the same shape RFC-007 settled on for `max_age` at `/authorize`,
//! and for the same reason: this framework owns no login UI, so it cannot
//! display a form, verify a password, or run a WebAuthn ceremony. It can
//! only recognise that the identity in hand is not fresh enough and say so
//! precisely enough for the caller to act. The caller decides whether that
//! means a re-login page, a step-up challenge, or a `403`.
//!
//! ## Freshness rides on the session, and is deliberately not renewed
//!
//! [`Session`](crate::auth::Session) stores the whole
//! [`Identity`](crate::auth::Identity), `attributes` included, so
//! `auth_time` survives into the session store and a handler holding a
//! session already has everything this gate needs. It records when the user
//! *authenticated*, not when they were last active, and nothing in this
//! crate refreshes it — so a long-lived session eventually stops satisfying
//! a gate even while it stays perfectly valid for ordinary requests. That is
//! the intended behaviour: "still signed in" and "just proved it" are
//! different questions, and this is the one that asks the second.
//!
//! ## Example
//!
//! ```
//! use authkestra_engine::auth::{
//!     Identity, ReproofRequirement, IDENTITY_ATTR_AUTH_TIME,
//!     IDENTITY_ATTR_STEP_UP_SATISFIED,
//! };
//! use std::collections::HashMap;
//!
//! // Enrolling a factor: prove it again within five minutes, and with a
//! // factor that satisfies this engine's step-up tier.
//! let gate = ReproofRequirement::new(300).require_step_up(true);
//!
//! let mut attributes = HashMap::new();
//! attributes.insert(IDENTITY_ATTR_AUTH_TIME.to_string(), "1000".to_string());
//! attributes.insert(
//!     IDENTITY_ATTR_STEP_UP_SATISFIED.to_string(),
//!     "true".to_string(),
//! );
//! let identity = Identity {
//!     provider_id: "local".into(),
//!     external_id: "alice".into(),
//!     email: None,
//!     username: None,
//!     attributes,
//! };
//!
//! assert!(gate.check_at(&identity, 1200).is_ok()); // 200s old — fine
//! assert!(gate.check_at(&identity, 1400).is_err()); // 400s old — re-prove
//! ```

use std::collections::HashMap;
use std::fmt;

use super::state::{Identity, IDENTITY_ATTR_AUTH_TIME, IDENTITY_ATTR_STEP_UP_SATISFIED};
use super::AuthError;

/// What an operation demands of the identity presenting it.
///
/// `#[non_exhaustive]`: build one with [`ReproofRequirement::new`] and the
/// builder methods. New dimensions of "is this proof good enough" belong
/// here as they arrive (a required `amr` value, say), and every one of them
/// would otherwise be a breaking change for callers that had nothing to do
/// with it — the same reasoning `MfaTokenClaims` and `Jwk` already carry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReproofRequirement {
    /// How old, in seconds, the identity's most recent authentication may
    /// be. See [`ReproofRequirement::new`] for why `0` is meaningful.
    pub max_age_secs: u64,
    /// Whether that authentication must also have satisfied this engine's
    /// step-up tier — see [`IDENTITY_ATTR_STEP_UP_SATISFIED`].
    pub require_step_up: bool,
}

impl ReproofRequirement {
    /// A requirement that the identity authenticated within the last
    /// `max_age_secs` seconds.
    ///
    /// `0` is a meaningful value, not "unset": it means *every* call must be
    /// preceded by a fresh authentication, because the comparison against it
    /// is inclusive (see [`ReproofRequirement::check_at`]).
    ///
    /// There is deliberately no default window. What counts as fresh depends
    /// entirely on what the gated operation grants — enrolling a factor that
    /// will outlive the session is not the same decision as revealing an
    /// email address — and a framework-chosen number would be obeyed far
    /// more often than it was reviewed.
    pub fn new(max_age_secs: u64) -> Self {
        Self {
            max_age_secs,
            require_step_up: false,
        }
    }

    /// Also require that the authentication satisfied this engine's step-up
    /// tier: either a step-up (MFA) challenge actually completed, or the
    /// sole primary [`AuthMethod`](crate::auth::AuthMethod) reported
    /// [`is_mfa_equivalent`](crate::auth::AuthMethod::is_mfa_equivalent).
    ///
    /// Worth turning on for enrolment specifically. An account that already
    /// has a second factor should not be able to add another one on the
    /// strength of the primary factor alone — that is precisely the
    /// escalation path a stolen session takes.
    ///
    /// Note what this cannot do: an account with no second factor enrolled
    /// *yet* has nothing to satisfy it with, so gating first-time enrolment
    /// on it locks the feature behind itself. Callers that want both
    /// behaviours generally set this from whether the user already has an
    /// enrolled factor ([`AuthMethod::has_enrolled`](crate::auth::AuthMethod::has_enrolled)).
    pub fn require_step_up(mut self, required: bool) -> Self {
        self.require_step_up = required;
        self
    }

    /// Checks `identity` against this requirement as of now.
    ///
    /// See [`ReproofRequirement::check_at`] for the semantics; this is that
    /// method with the current Unix time.
    pub fn check(&self, identity: &Identity) -> Result<(), ReproofFailure> {
        self.check_at(identity, chrono::Utc::now().timestamp())
    }

    /// Checks `identity` against this requirement as of `now` (a Unix
    /// timestamp in seconds).
    ///
    /// Three decisions are load-bearing, and all three match what RFC-007
    /// settled for `max_age` at `/authorize` — a gate that answered "is this
    /// proof recent enough" differently depending on which entry point asked
    /// would be worse than either answer alone:
    ///
    /// - **A missing or unparseable `auth_time` fails closed**, as
    ///   [`ReproofFailure::FreshnessUnknown`]. An `Identity` that never
    ///   passed through [`Engine::authenticate`](crate::Engine::authenticate)
    ///   carries no evidence of when — or whether — it freshly
    ///   authenticated. Treating "we don't know" as "recent enough" would
    ///   make the gate silently absent for exactly the federated and
    ///   application-constructed identities most likely to reach it.
    ///
    /// - **The comparison is inclusive.** `now - auth_time >= max_age_secs`
    ///   is stale. `auth_time` has whole-second granularity, so a strict `>`
    ///   would let an authentication landing in the same wall-clock second
    ///   as the request satisfy `max_age_secs == 0` — a control whose
    ///   applicability turned on sub-second timing the caller cannot see.
    ///
    /// - **An `auth_time` in the future is treated as fresh, not rejected.**
    ///   It is reachable through ordinary clock skew between instances of
    ///   the same deployment, which this crate already tolerates elsewhere
    ///   (`token::DEFAULT_LEEWAY_SECS`), and failing on it would break a
    ///   correctly configured deployment for a condition it cannot fix from
    ///   the calling side. It is not a way to *bypass* the gate: the value
    ///   is stamped server-side by `Engine::authenticate` and reaches this
    ///   check from the caller's own session store, never from the client.
    ///
    /// Only the first failure is reported. Staleness is checked before
    /// step-up because it subsumes it — an identity that has to re-prove
    /// from scratch will re-establish step-up on the way through, so
    /// reporting [`ReproofFailure::StepUpNotSatisfied`] for an identity that
    /// is *also* too old would send the caller after the narrower of the two
    /// remedies.
    pub fn check_at(&self, identity: &Identity, now: i64) -> Result<(), ReproofFailure> {
        let auth_time = parse_auth_time(&identity.attributes).ok_or_else(|| {
            tracing::warn!(
                user_id = %identity.external_id,
                "re-proof gate refused an identity carrying no usable auth_time; \
                 it did not come from Engine::authenticate"
            );
            ReproofFailure::FreshnessUnknown
        })?;

        let age_secs = now.saturating_sub(auth_time);
        if age_secs >= 0 && (age_secs as u64) >= self.max_age_secs {
            tracing::info!(
                user_id = %identity.external_id,
                age_secs,
                max_age_secs = self.max_age_secs,
                "re-proof gate refused a stale identity"
            );
            return Err(ReproofFailure::Stale {
                auth_time,
                age_secs,
                max_age_secs: self.max_age_secs,
            });
        }

        if self.require_step_up
            && identity.attributes.get(IDENTITY_ATTR_STEP_UP_SATISFIED) != Some(&"true".to_string())
        {
            tracing::info!(
                user_id = %identity.external_id,
                "re-proof gate refused an identity whose authentication did not satisfy step-up"
            );
            return Err(ReproofFailure::StepUpNotSatisfied);
        }

        tracing::debug!(
            user_id = %identity.external_id,
            age_secs,
            "re-proof gate satisfied"
        );
        Ok(())
    }
}

/// Reads [`IDENTITY_ATTR_AUTH_TIME`] out of an identity's attributes.
///
/// Anything that does not parse as an `i64` is treated as absent rather than
/// as an error to propagate: the attribute is a string map entry, so a
/// malformed value and a missing one are the same amount of evidence about
/// when the user authenticated, which is none.
fn parse_auth_time(attributes: &HashMap<String, String>) -> Option<i64> {
    attributes.get(IDENTITY_ATTR_AUTH_TIME)?.parse::<i64>().ok()
}

/// Why a [`ReproofRequirement`] was not satisfied.
///
/// The variants are distinguishable on purpose: the remedies differ. A
/// caller typically sends [`ReproofFailure::Stale`] and
/// [`ReproofFailure::FreshnessUnknown`] to a re-login page, and
/// [`ReproofFailure::StepUpNotSatisfied`] to a step-up challenge — the user
/// is still who they said they were, they just have not proved it strongly
/// enough for this particular operation.
///
/// What a caller should *not* do is forward the detail to the client
/// verbatim. `auth_time` and the exact configured window are server-side
/// facts about the account, and an endpoint that reports them turns the gate
/// into an oracle for how recently someone else logged in.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReproofFailure {
    /// The identity carries no usable [`IDENTITY_ATTR_AUTH_TIME`], so there
    /// is no evidence it ever freshly authenticated. See
    /// [`ReproofRequirement::check_at`] for why this fails rather than
    /// passes.
    FreshnessUnknown,
    /// The identity authenticated too long ago.
    Stale {
        /// The Unix timestamp the identity authenticated at.
        auth_time: i64,
        /// How many seconds ago that was, as of the check.
        age_secs: i64,
        /// The window it had to fall within.
        max_age_secs: u64,
    },
    /// The identity is fresh enough, but its authentication did not satisfy
    /// this engine's step-up tier and the requirement asked for it.
    StepUpNotSatisfied,
}

impl fmt::Display for ReproofFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FreshnessUnknown => write!(
                f,
                "identity carries no auth_time, so its freshness cannot be established"
            ),
            Self::Stale {
                age_secs,
                max_age_secs,
                ..
            } => write!(
                f,
                "identity authenticated {age_secs}s ago, outside the {max_age_secs}s window"
            ),
            Self::StepUpNotSatisfied => {
                write!(f, "identity's authentication did not satisfy step-up")
            }
        }
    }
}

impl std::error::Error for ReproofFailure {}

impl From<ReproofFailure> for AuthError {
    /// Maps to [`AuthError::Credentials`], not `InvalidInput`: nothing about
    /// the *request* was malformed. The caller presented a valid identity
    /// whose proof of identity was not good enough for what it asked to do.
    fn from(failure: ReproofFailure) -> Self {
        AuthError::Credentials(failure.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `auth_time` is a wall-clock Unix timestamp, so the tests pin both
    /// ends of the comparison rather than calling `check`, which reads the
    /// real clock. `check` itself is exercised once, at the bottom.
    const AUTH_TIME: i64 = 1_000_000;

    fn identity_with(attrs: &[(&str, &str)]) -> Identity {
        Identity {
            provider_id: "test".into(),
            external_id: "alice".into(),
            email: None,
            username: None,
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn authenticated_at(ts: i64) -> Identity {
        identity_with(&[(IDENTITY_ATTR_AUTH_TIME, &ts.to_string())])
    }

    #[test]
    fn an_identity_inside_the_window_passes() {
        let gate = ReproofRequirement::new(300);
        assert_eq!(
            gate.check_at(&authenticated_at(AUTH_TIME), AUTH_TIME + 299),
            Ok(())
        );
    }

    #[test]
    fn the_boundary_is_inclusive() {
        // Exactly `max_age` seconds old has used up its allowance. A strict
        // `>` here would make `max_age_secs == 0` depend on sub-second
        // timing the caller cannot see — see `check_at`'s docs.
        let gate = ReproofRequirement::new(300);
        assert_eq!(
            gate.check_at(&authenticated_at(AUTH_TIME), AUTH_TIME + 299),
            Ok(())
        );
        assert!(matches!(
            gate.check_at(&authenticated_at(AUTH_TIME), AUTH_TIME + 300),
            Err(ReproofFailure::Stale { .. })
        ));
    }

    #[test]
    fn zero_always_requires_a_fresh_proof() {
        // Not "unset": an authentication in the same wall-clock second as
        // the check is still not fresh enough.
        let gate = ReproofRequirement::new(0);
        assert!(matches!(
            gate.check_at(&authenticated_at(AUTH_TIME), AUTH_TIME),
            Err(ReproofFailure::Stale {
                age_secs: 0,
                max_age_secs: 0,
                ..
            })
        ));
    }

    #[test]
    fn a_stale_failure_reports_what_it_measured() {
        let gate = ReproofRequirement::new(60);
        assert_eq!(
            gate.check_at(&authenticated_at(AUTH_TIME), AUTH_TIME + 90),
            Err(ReproofFailure::Stale {
                auth_time: AUTH_TIME,
                age_secs: 90,
                max_age_secs: 60,
            })
        );
    }

    #[test]
    fn a_missing_auth_time_fails_closed() {
        // An identity that never passed through `Engine::authenticate`
        // carries no evidence of when it authenticated. "We don't know" is
        // treated as "too old", never as "recent enough".
        let gate = ReproofRequirement::new(300);
        assert_eq!(
            gate.check_at(&identity_with(&[]), AUTH_TIME),
            Err(ReproofFailure::FreshnessUnknown)
        );
    }

    #[test]
    fn an_unparseable_auth_time_fails_closed() {
        // Same amount of evidence as a missing one, so the same verdict —
        // and specifically not a pass, which is what treating the parse
        // failure as "no requirement present" would have produced.
        for value in ["", "not-a-number", "12.5", "9999999999999999999999"] {
            let identity = identity_with(&[(IDENTITY_ATTR_AUTH_TIME, value)]);
            assert_eq!(
                gate_300().check_at(&identity, AUTH_TIME),
                Err(ReproofFailure::FreshnessUnknown),
                "{value:?} should not have been usable as an auth_time"
            );
        }
    }

    fn gate_300() -> ReproofRequirement {
        ReproofRequirement::new(300)
    }

    #[test]
    fn an_auth_time_in_the_future_is_treated_as_fresh() {
        // Reachable through ordinary clock skew between instances, and not
        // a bypass: the value is stamped server-side and reaches the check
        // from the caller's own session store, never from the client.
        assert_eq!(
            gate_300().check_at(&authenticated_at(AUTH_TIME + 500), AUTH_TIME),
            Ok(())
        );
    }

    #[test]
    fn step_up_is_not_required_unless_asked_for() {
        // The default requirement asks only about freshness, so an identity
        // with no step-up attribute at all still passes.
        assert_eq!(
            gate_300().check_at(&authenticated_at(AUTH_TIME), AUTH_TIME + 10),
            Ok(())
        );
    }

    #[test]
    fn step_up_required_and_satisfied_passes() {
        let identity = identity_with(&[
            (IDENTITY_ATTR_AUTH_TIME, &AUTH_TIME.to_string()),
            (IDENTITY_ATTR_STEP_UP_SATISFIED, "true"),
        ]);
        assert_eq!(
            gate_300()
                .require_step_up(true)
                .check_at(&identity, AUTH_TIME + 10),
            Ok(())
        );
    }

    #[test]
    fn step_up_required_but_absent_is_refused() {
        assert_eq!(
            gate_300()
                .require_step_up(true)
                .check_at(&authenticated_at(AUTH_TIME), AUTH_TIME + 10),
            Err(ReproofFailure::StepUpNotSatisfied)
        );
    }

    #[test]
    fn only_the_literal_true_satisfies_step_up() {
        // `IDENTITY_ATTR_STEP_UP_SATISFIED` is documented as absent-or-
        // `"true"`, never `"false"`. Anything else present is not a value
        // this engine wrote, so it is not taken as satisfaction.
        for value in ["false", "1", "yes", "TRUE", ""] {
            let identity = identity_with(&[
                (IDENTITY_ATTR_AUTH_TIME, &AUTH_TIME.to_string()),
                (IDENTITY_ATTR_STEP_UP_SATISFIED, value),
            ]);
            assert_eq!(
                gate_300()
                    .require_step_up(true)
                    .check_at(&identity, AUTH_TIME + 10),
                Err(ReproofFailure::StepUpNotSatisfied),
                "{value:?} should not have counted as step-up satisfied"
            );
        }
    }

    #[test]
    fn staleness_is_reported_ahead_of_step_up() {
        // Both fail here. Staleness subsumes step-up — re-proving from
        // scratch re-establishes it — so reporting `StepUpNotSatisfied`
        // would send the caller after the narrower remedy.
        assert_eq!(
            gate_300()
                .require_step_up(true)
                .check_at(&authenticated_at(AUTH_TIME), AUTH_TIME + 600),
            Err(ReproofFailure::Stale {
                auth_time: AUTH_TIME,
                age_secs: 600,
                max_age_secs: 300,
            })
        );
    }

    #[test]
    fn require_step_up_is_settable_back_to_false() {
        let gate = gate_300().require_step_up(true).require_step_up(false);
        assert!(!gate.require_step_up);
        assert_eq!(
            gate.check_at(&authenticated_at(AUTH_TIME), AUTH_TIME + 10),
            Ok(())
        );
    }

    #[test]
    fn failures_map_to_a_credentials_error() {
        // Not `InvalidInput`: nothing about the request was malformed.
        let err: AuthError = ReproofFailure::StepUpNotSatisfied.into();
        assert!(matches!(err, AuthError::Credentials(_)));
    }

    #[test]
    fn failures_describe_themselves() {
        assert!(ReproofFailure::FreshnessUnknown
            .to_string()
            .contains("auth_time"));
        assert!(ReproofFailure::Stale {
            auth_time: AUTH_TIME,
            age_secs: 600,
            max_age_secs: 300,
        }
        .to_string()
        .contains("600s ago"));
        assert!(ReproofFailure::StepUpNotSatisfied
            .to_string()
            .contains("step-up"));
    }

    #[test]
    fn check_reads_the_real_clock() {
        let now = chrono::Utc::now().timestamp();
        assert_eq!(gate_300().check(&authenticated_at(now)), Ok(()));
        assert!(matches!(
            gate_300().check(&authenticated_at(now - 3600)),
            Err(ReproofFailure::Stale { .. })
        ));
    }
}
