//! Magic-link authentication: prove control of an inbox, get an identity.
//!
//! See `docs/rfc-010-magic-link.md` for the design record. The short version
//! is that this module owns a deliberately small slice of what people mean by
//! "magic link":
//!
//! ```text
//! application                          this module
//! -----------                          -----------
//! resolve address -> subject
//!                                      mint(subject, ttl, binding)
//! render + send the mail
//!                     ... user follows the link ...
//! receive the token
//!                                      authenticate(MagicLink { .. })
//!                                         -> consume exactly once
//!                                         -> Identity
//! establish the session
//! ```
//!
//! It does not own the address book, the mail transport, the template, or the
//! question of whether an address corresponds to an account. The framework
//! owns no user table (decision 0005), so it cannot answer the last one, and
//! owning the transport would mean taking positions on SMTP, queueing,
//! retries and bounce handling — none of which is authentication.
//!
//! One consequence is worth stating plainly: **this module cannot leak
//! whether an account exists**, because it is never told. Whether
//! `POST /login` reveals that is decided entirely by what the application
//! returns and how long it takes. See RFC-010 §4.8.

use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::state::METHOD_NAME_MAGIC_LINK;
use crate::auth::{AuthError, AuthInput, AuthMethod, Identity};
use crate::store::{AtomicConsume, KvStore};

/// How many bytes of CSPRNG output back a minted secret.
///
/// 256 bits. The size is what makes the rest of this module's threat model
/// tractable: there is no dictionary to attack, so the stored hash needs no
/// KDF (see [`hash_secret`]), and brute force is not a thing an attempt
/// counter has to defend against the way it must for a six-digit code.
const SECRET_BYTES: usize = 32;

/// Whether a minted link may be followed from anywhere, or only from the
/// context that asked for it.
///
/// A link is a bearer credential sitting in a URL, so anyone who obtains it
/// authenticates — shared inboxes, forwarded mail, a synced browser history,
/// a screenshot in a support ticket. Binding it to the requesting context
/// closes that, at the cost of "request on my laptop, open on my phone",
/// which for some products is the main way the feature is used.
///
/// Neither answer is safe to pick on an application's behalf, so this type
/// makes it choose. [`AnyContext`](Self::AnyContext) is spelled out rather
/// than expressed as an `Option::None` for that reason: the riskier choice
/// should be something somebody typed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MagicLinkBinding {
    /// Valid only when presented with this exact value — a nonce the
    /// application set as a cookie when it asked for the link.
    ///
    /// The value must be unguessable. Binding to something an attacker can
    /// predict (a username, an email address) reproduces
    /// [`AnyContext`](Self::AnyContext) while looking like it does not.
    SameContext(String),
    /// Valid from anywhere. Cross-device works; a forwarded link
    /// authenticates whoever follows it.
    AnyContext,
}

/// A freshly minted link secret. Returned once and never recoverable.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct MagicLinkToken {
    /// The secret to place in the URL.
    ///
    /// Only ever held in memory here — the store keeps a hash (RFC-010 §4.4).
    /// If sending the mail fails, mint a new one; this cannot be read back.
    pub secret: String,
    /// Unix seconds after which the secret stops being accepted.
    ///
    /// Absolute rather than a duration so the application can render it in
    /// the mail without recomputing what it already asked for.
    pub expires_at: i64,
}

/// What the store holds against the hash of a secret.
///
/// Note what is *not* here: the secret. See [`hash_secret`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MagicLinkRecord {
    /// The subject the application resolved before minting.
    pub subject: String,
    /// The binding chosen at mint time.
    pub binding: MagicLinkBinding,
}

/// Derives the store key for a secret.
///
/// SHA-256, not a password hash, and that is not an oversight. The secret is
/// [`SECRET_BYTES`] of CSPRNG output rather than something a human chose, so
/// there is no dictionary for a slow KDF to frustrate — Argon2 here would add
/// latency to every verification and buy nothing.
///
/// Hashing at all is the point: stores are routinely Redis or Postgres,
/// shared with other workloads, backed up, and visible to more operators than
/// the application process is. Holding live bearer credentials in plaintext
/// turns a read-only store compromise into account takeover for every pending
/// link.
fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Magic-link authentication over any store that can atomically consume.
///
/// The [`AtomicConsume`] bound is load-bearing rather than a convenience: see
/// [`AuthMethod::authenticate`] for why a `used: bool` flag would not do.
pub struct MagicLinkAuthMethod<S> {
    store: S,
}

impl<S> MagicLinkAuthMethod<S>
where
    S: KvStore<MagicLinkRecord> + AtomicConsume<MagicLinkRecord>,
{
    /// Wrap a store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Mint a single-use secret for an already-resolved subject.
    ///
    /// `ttl` is required rather than defaulted, deliberately. Any default
    /// would be wrong for somebody — fifteen minutes is generous for a
    /// consumer login and reckless for an administrative one — and the
    /// failure is silent, since a too-long window produces no error, just a
    /// wider one. Naming it puts the number where a reviewer can see it.
    ///
    /// Minting twice for the same subject leaves both secrets live until they
    /// expire. That is intentional for now — the first mail may simply be
    /// slow — but see RFC-010 §7.
    #[tracing::instrument(skip(self, binding), fields(ttl_secs = ttl.as_secs()))]
    pub async fn mint(
        &self,
        subject: &str,
        ttl: Duration,
        binding: MagicLinkBinding,
    ) -> Result<MagicLinkToken, AuthError> {
        let mut bytes = [0u8; SECRET_BYTES];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
        let secret = URL_SAFE_NO_PAD.encode(bytes);

        let record = MagicLinkRecord {
            subject: subject.to_string(),
            binding,
        };

        self.store
            .set(&hash_secret(&secret), record, ttl)
            .await
            .map_err(|e| AuthError::Internal(format!("magic-link store write failed: {e}")))?;

        let expires_at = chrono::Utc::now().timestamp() + ttl.as_secs() as i64;
        tracing::debug!(subject = %subject, expires_at, "minted a magic link");

        Ok(MagicLinkToken { secret, expires_at })
    }
}

#[async_trait]
impl<S> AuthMethod for MagicLinkAuthMethod<S>
where
    S: KvStore<MagicLinkRecord> + AtomicConsume<MagicLinkRecord> + Send + Sync + 'static,
{
    fn name(&self) -> &str {
        METHOD_NAME_MAGIC_LINK
    }

    /// Consume a secret and yield the subject it was minted for.
    ///
    /// Consumption goes through [`AtomicConsume::consume`], which fetches and
    /// removes in one operation. The obvious alternative — store a
    /// `used: bool` and set it after checking — is a TOCTOU race where two
    /// concurrent requests both read `false` and both succeed. That is not a
    /// theoretical concern here: mail clients and security appliances issue
    /// concurrent prefetches of the same URL routinely, so the race is
    /// reached in ordinary operation, not only under attack.
    ///
    /// Every failure returns [`AuthError::InvalidCredentials`], whether the
    /// secret was never valid, already used, expired, or presented from the
    /// wrong context. Distinguishing them in the return value would hand a
    /// caller an oracle; the distinction is logged instead.
    ///
    /// A binding mismatch consumes the secret rather than leaving it
    /// available for a retry. That is the fail-closed reading: a link
    /// presented from a context that did not request it is the exact
    /// circumstance the binding exists to detect, so burning it is the
    /// correct response — and it means an attacker holding a stolen link gets
    /// exactly one attempt, which is why comparing the binding in constant
    /// time would buy nothing here.
    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError> {
        let AuthInput::MagicLink { token, binding } = input else {
            tracing::debug!("declining: input is not a magic link");
            return Err(AuthError::InvalidInput);
        };

        let record = self
            .store
            .consume(&hash_secret(&token))
            .await
            .map_err(|e| AuthError::Internal(format!("magic-link store read failed: {e}")))?;

        let Some(record) = record else {
            // Unknown, expired, or already consumed — indistinguishable here
            // by construction, since an expired entry is simply gone.
            tracing::warn!("magic link rejected: no live secret matched");
            return Err(AuthError::InvalidCredentials);
        };

        if let MagicLinkBinding::SameContext(expected) = &record.binding {
            if binding.as_deref() != Some(expected.as_str()) {
                tracing::warn!(
                    subject = %record.subject,
                    presented = binding.is_some(),
                    "magic link rejected: context binding mismatch; the secret has been consumed"
                );
                return Err(AuthError::InvalidCredentials);
            }
        }

        tracing::info!(subject = %record.subject, "magic link accepted");

        Ok(Identity {
            provider_id: METHOD_NAME_MAGIC_LINK.to_string(),
            external_id: record.subject,
            email: None,
            username: None,
            attributes: Default::default(),
        })
    }

    /// Always `false`, as a statement rather than an inherited default.
    ///
    /// There is no enrolment ceremony: any subject the application can
    /// resolve can be sent a link. Reporting `true` would tell the
    /// step-up logic a factor exists to challenge with, which is not so.
    async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
        Ok(false)
    }

    /// Always `false`. Proving control of an inbox is one factor, and an
    /// account whose recovery address is that same inbox gains nothing from
    /// presenting it twice.
    fn is_mfa_equivalent(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::MemoryStore;

    const TTL: Duration = Duration::from_secs(300);

    fn method() -> MagicLinkAuthMethod<MemoryStore<MagicLinkRecord>> {
        MagicLinkAuthMethod::new(MemoryStore::new())
    }

    fn follow(token: &str, binding: Option<&str>) -> AuthInput {
        AuthInput::MagicLink {
            token: token.to_string(),
            binding: binding.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn a_minted_link_authenticates_the_subject_it_was_minted_for() {
        let m = method();
        let minted = m
            .mint("alice", TTL, MagicLinkBinding::AnyContext)
            .await
            .unwrap();

        let identity = m.authenticate(follow(&minted.secret, None)).await.unwrap();

        assert_eq!(identity.external_id, "alice");
        assert_eq!(identity.provider_id, METHOD_NAME_MAGIC_LINK);
    }

    /// The property the whole method rests on. A second use is not a
    /// degraded success, it is a failure.
    #[tokio::test]
    async fn a_link_works_exactly_once() {
        let m = method();
        let minted = m
            .mint("alice", TTL, MagicLinkBinding::AnyContext)
            .await
            .unwrap();

        assert!(m.authenticate(follow(&minted.secret, None)).await.is_ok());
        assert!(matches!(
            m.authenticate(follow(&minted.secret, None)).await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    /// Expiry needs no separate test: a lapsed entry is gone from the store,
    /// so it is the same path as a secret that never existed. This pins that
    /// path.
    #[tokio::test]
    async fn an_unknown_secret_is_refused() {
        let m = method();
        assert!(matches!(
            m.authenticate(follow("not-a-real-secret", None)).await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn a_bound_link_needs_its_binding() {
        let m = method();
        let minted = m
            .mint(
                "alice",
                TTL,
                MagicLinkBinding::SameContext("nonce-1".into()),
            )
            .await
            .unwrap();

        let identity = m
            .authenticate(follow(&minted.secret, Some("nonce-1")))
            .await
            .unwrap();
        assert_eq!(identity.external_id, "alice");
    }

    #[tokio::test]
    async fn a_bound_link_presented_without_its_binding_is_refused() {
        let m = method();
        let minted = m
            .mint(
                "alice",
                TTL,
                MagicLinkBinding::SameContext("nonce-1".into()),
            )
            .await
            .unwrap();

        assert!(matches!(
            m.authenticate(follow(&minted.secret, None)).await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    /// A forwarded link is the attack `SameContext` exists to stop, so
    /// presenting someone else's binding must not work.
    #[tokio::test]
    async fn a_bound_link_refuses_the_wrong_binding() {
        let m = method();
        let minted = m
            .mint(
                "alice",
                TTL,
                MagicLinkBinding::SameContext("nonce-1".into()),
            )
            .await
            .unwrap();

        assert!(matches!(
            m.authenticate(follow(&minted.secret, Some("nonce-2")))
                .await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    /// Fail-closed, and documented as such on `authenticate`: a link
    /// presented from the wrong context is the circumstance the binding
    /// exists to detect, so it is burned rather than left for a retry. This
    /// is also what limits an attacker to a single guess, which is the
    /// reason the comparison need not be constant-time.
    #[tokio::test]
    async fn a_binding_mismatch_consumes_the_secret() {
        let m = method();
        let minted = m
            .mint(
                "alice",
                TTL,
                MagicLinkBinding::SameContext("nonce-1".into()),
            )
            .await
            .unwrap();

        assert!(m
            .authenticate(follow(&minted.secret, Some("wrong")))
            .await
            .is_err());

        // Even the correct binding cannot rescue it now.
        assert!(matches!(
            m.authenticate(follow(&minted.secret, Some("nonce-1")))
                .await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn an_unbound_link_ignores_a_presented_binding() {
        let m = method();
        let minted = m
            .mint("alice", TTL, MagicLinkBinding::AnyContext)
            .await
            .unwrap();

        let identity = m
            .authenticate(follow(&minted.secret, Some("irrelevant")))
            .await
            .unwrap();
        assert_eq!(identity.external_id, "alice");
    }

    /// RFC-010 §4.4. A read-only store compromise must not be account
    /// takeover, so the secret must not be recoverable from what was written.
    #[tokio::test]
    async fn the_store_never_holds_the_secret() {
        let store = MemoryStore::<MagicLinkRecord>::new();
        let m = MagicLinkAuthMethod::new(store.clone());
        let minted = m
            .mint("alice", TTL, MagicLinkBinding::AnyContext)
            .await
            .unwrap();

        // The key is a hash, so the secret itself addresses nothing.
        assert!(store.get(&minted.secret).await.unwrap().is_none());

        let record = store.get(&hash_secret(&minted.secret)).await.unwrap();
        let record = record.expect("the hash should address the record");
        assert_eq!(record.subject, "alice");
        let serialized = serde_json::to_string(&record).unwrap();
        assert!(
            !serialized.contains(&minted.secret),
            "the stored record must not carry the secret"
        );
    }

    #[tokio::test]
    async fn two_mints_produce_different_secrets() {
        let m = method();
        let a = m
            .mint("alice", TTL, MagicLinkBinding::AnyContext)
            .await
            .unwrap();
        let b = m
            .mint("alice", TTL, MagicLinkBinding::AnyContext)
            .await
            .unwrap();
        assert_ne!(a.secret, b.secret);
    }

    #[tokio::test]
    async fn another_methods_input_is_declined_rather_than_misread() {
        let m = method();
        assert!(matches!(
            m.authenticate(AuthInput::Token("bearer".into())).await,
            Err(AuthError::InvalidInput)
        ));
    }

    /// RFC-010 §4.10. Both are deliberate statements, so a change to either
    /// should have to break a test.
    #[tokio::test]
    async fn magic_link_is_not_a_second_factor_and_enrols_nothing() {
        let m = method();
        assert!(!m.is_mfa_equivalent());
        assert!(!m.has_enrolled("alice").await.unwrap());
        assert_eq!(m.name(), "magic-link");
    }
}
