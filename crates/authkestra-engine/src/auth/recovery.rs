//! Recovery codes: a look-up secret authenticator.
//!
//! See `docs/rfc-012-recovery-codes.md` for the design record.
//!
//! A set of codes, generated once, shown once, each usable once — the thing
//! you print and put in a drawer for the day your phone is in a river. NIST
//! SP 800-63B §5.1.2 calls this a look-up secret authenticator, and that term
//! is used here deliberately: these are a fallback for *whatever* the account
//! has registered, not an appendix to TOTP. Tying them to one factor would
//! reproduce the problem they exist to solve, since an account with a passkey
//! and no TOTP would have no recovery path at all.
//!
//! Two things make this different from the other delivered-secret methods on
//! the same track. It **enrols**, so generation is gated by
//! [`ReproofRequirement`](crate::auth::ReproofRequirement) — this is the
//! first caller that gate has ever had. And the codes are **long-lived**, so
//! the "it expires in five minutes" reasoning that carried a lot of weight
//! for magic link and OTP is unavailable.

use async_trait::async_trait;
use base32::Alphabet;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::state::METHOD_NAME_RECOVERY_CODE;
use crate::auth::store::CredentialStore;
use crate::auth::{AuthError, AuthInput, AuthMethod, Identity, ReproofRequirement};

/// The credential type recovery codes are stored under.
const CRED_TYPE: &str = "recovery-code";

/// Bytes of CSPRNG output behind each code: 80 bits.
///
/// NIST SP 800-63B §5.1.2 permits look-up secrets as low as 20 bits provided
/// the verifier throttles. This takes the other branch, because a throttle
/// for a *long-lived* secret has nowhere natural to live: OTP could hang an
/// attempt budget off a challenge that expires in five minutes, but a
/// recovery set lives for years, and the equivalent counter would have to be
/// reset, aged and explained. Enough entropy removes the apparatus.
const CODE_BYTES: usize = 10;

/// How many groups a rendered code is split into, and how long each is.
///
/// Purely legibility: these get read off paper and typed by someone who is
/// already having a bad day.
const GROUP_LEN: usize = 4;

/// What the store holds for one unredeemed code.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RecoveryCodeCredential {
    /// Stable id, so redemption can name exactly this code.
    pub credential_id: String,
    /// SHA-256 of the code, never the code.
    pub code_hash: String,
}

/// Hashes a code for storage and lookup.
///
/// SHA-256, and unlike the other two methods on this track the choice is
/// worth arguing rather than assuming. These are the only long-lived secret
/// of the three, so a store compromise gives an attacker unlimited time
/// instead of five minutes — which is exactly the situation a memory-hard KDF
/// is usually reached for.
///
/// It still lands here: [`CODE_BYTES`] of uniform random has no dictionary,
/// so a KDF slows an attacker by a constant factor against a search space
/// that is already infeasible. What a KDF actually buys is protection for
/// *low-entropy* secrets, which the entropy floor has already ruled out by
/// construction.
fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    // Normalised first, so the stored hash does not depend on how the user
    // happened to type the separators back in.
    hasher.update(normalise(code).as_bytes());
    base32::encode(Alphabet::Rfc4648 { padding: false }, &hasher.finalize())
}

/// Strips formatting and case from a typed code.
///
/// The rendered form carries dashes for legibility and the alphabet is
/// case-insensitive, so `4kdw-9jmq` and `4KDW9JMQ` are the same secret. A
/// verifier that disagreed would reject correct codes depending on how
/// carefully someone retyped them, which is the failure this method exists to
/// avoid rather than cause.
fn normalise(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Generates one code, rendered in groups.
fn generate_code() -> String {
    let mut bytes = [0u8; CODE_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    let raw = base32::encode(Alphabet::Rfc4648 { padding: false }, &bytes);
    raw.as_bytes()
        .chunks(GROUP_LEN)
        .map(|c| std::str::from_utf8(c).unwrap_or_default().to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// A factor-agnostic fallback across whatever an account has registered.
pub struct RecoveryCodeAuthMethod<S: CredentialStore> {
    store: S,
}

impl<S: CredentialStore> RecoveryCodeAuthMethod<S> {
    /// Wrap a credential store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Generate a fresh set, replacing any existing one.
    ///
    /// The returned codes are the only time they are ever readable: the store
    /// keeps hashes. There is deliberately no "show them to me again".
    ///
    /// `gate` is checked before anything is written, and the account is named
    /// by `identity` rather than beside it — RFC-009 §4.6's rule, which
    /// exists because a re-proved session for one account being allowed to
    /// name another's id reinstates the confused deputy one level up.
    ///
    /// On `require_step_up`: an account with no second factor has nothing to
    /// satisfy it with, so demanding it for a first enrolment locks the
    /// feature behind itself — and a recovery set is plausibly the *first*
    /// thing a passkey-only account enrols. The intended pattern is to set it
    /// from [`AuthMethod::has_enrolled`], so an account that already has a
    /// fallback must use it and one that does not is gated on freshness
    /// alone. That choice is the caller's; this method does not make it.
    #[tracing::instrument(skip(self, gate), fields(count = count))]
    pub async fn generate(
        &self,
        identity: &Identity,
        gate: &ReproofRequirement,
        count: u8,
    ) -> Result<Vec<String>, AuthError> {
        gate.check(identity)?;

        if count == 0 {
            // A set with no codes is a fallback that cannot be used. Far more
            // likely a caller bug than an intent.
            return Err(AuthError::InvalidInput);
        }

        let user_id = identity.external_id.as_str();

        // Snapshot what exists before writing, so the old set can be removed
        // by id afterwards.
        let existing = self.load(user_id).await?;

        let mut codes = Vec::with_capacity(count as usize);
        for i in 0..count {
            let code = generate_code();
            let credential = RecoveryCodeCredential {
                // Unique per code and unpredictable, since it is what
                // redemption names when it deletes.
                credential_id: format!("{CRED_TYPE}:{user_id}:{i}:{}", hash_code(&code)),
                code_hash: hash_code(&code),
            };
            self.store
                .save_credential(
                    user_id,
                    CRED_TYPE,
                    serde_json::to_value(&credential)
                        .map_err(|e| AuthError::Internal(e.to_string()))?,
                )
                .await?;
            codes.push(code);
        }

        // Only now. Deleting first would leave a window with no recovery path
        // at all, which is precisely when a user is most likely to be
        // mid-panic — briefly holding two valid sets is the smaller failure.
        for old in existing {
            match self
                .store
                .delete_credential(user_id, CRED_TYPE, &old.credential_id)
                .await
            {
                Ok(_) => {}
                // A store that cannot delete cannot retire the old set, which
                // would leave both live indefinitely. The new codes are
                // already stored, so failing here would be worse than saying
                // so loudly.
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "could not retire the previous recovery set; both are now live"
                    );
                    return Err(e);
                }
            }
        }

        tracing::info!(user_id = %user_id, count, "generated a recovery code set");
        Ok(codes)
    }

    /// How many unredeemed codes remain.
    ///
    /// Takes an identity rather than a bare id for the same reason
    /// [`Self::generate`] does. Not gated: it reveals a count to someone who
    /// has already authenticated as the account, and the alternative —
    /// finding out you are out of codes at the moment you need one — is the
    /// failure this whole method exists to prevent.
    pub async fn remaining(&self, identity: &Identity) -> Result<usize, AuthError> {
        Ok(self.load(&identity.external_id).await?.len())
    }

    async fn load(&self, user_id: &str) -> Result<Vec<RecoveryCodeCredential>, AuthError> {
        let raw = self.store.get_credentials(user_id, CRED_TYPE).await?;
        Ok(raw
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect())
    }
}

#[async_trait]
impl<S: CredentialStore + 'static> AuthMethod for RecoveryCodeAuthMethod<S> {
    fn name(&self) -> &str {
        METHOD_NAME_RECOVERY_CODE
    }

    /// Redeem a code.
    ///
    /// Single use is **won, not tidied up afterwards**. The code is looked up
    /// by hash and then accepted only if `delete_credential` reports that
    /// *this* call removed it — which the `CredentialStore` contract requires
    /// to be exclusive among concurrent callers naming the same id.
    ///
    /// Checking and then deleting would be the same defect OTP shipped and
    /// had to fix: it holds in serial tests and dissolves the moment two
    /// requests arrive together. A look-up secret that can be redeemed twice
    /// is not single use.
    ///
    /// Every failure returns [`AuthError::InvalidCredentials`] — unknown
    /// code, already redeemed, lost the race — so nothing here is an oracle.
    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError> {
        let AuthInput::RecoveryCode { user_id, code } = input else {
            tracing::debug!("declining: input is not a recovery code");
            return Err(AuthError::InvalidInput);
        };

        let presented = hash_code(&code);
        let candidates = self.load(&user_id).await?;

        let Some(found) = candidates.into_iter().find(|c| c.code_hash == presented) else {
            tracing::warn!("recovery code rejected: no unredeemed code matched");
            return Err(AuthError::InvalidCredentials);
        };

        let claimed = self
            .store
            .delete_credential(&user_id, CRED_TYPE, &found.credential_id)
            .await?;

        if !claimed {
            tracing::warn!("recovery code rejected: redeemed concurrently");
            return Err(AuthError::InvalidCredentials);
        }

        tracing::info!(user_id = %user_id, "recovery code redeemed");

        Ok(Identity {
            provider_id: METHOD_NAME_RECOVERY_CODE.to_string(),
            external_id: user_id,
            email: None,
            username: None,
            attributes: Default::default(),
        })
    }

    /// Whether the account has a fallback it can actually use.
    ///
    /// "At least one **unredeemed** code", not "has ever generated a set".
    /// The difference matters because this is the signal RFC-009 tells
    /// callers to drive `require_step_up` from: an account down to zero has
    /// no fallback, and reporting `true` would tell the gate a factor exists
    /// to step up with when none does.
    async fn has_enrolled(&self, user_id: &str) -> Result<bool, AuthError> {
        Ok(!self.load(user_id).await?.is_empty())
    }

    /// Always `false`.
    ///
    /// This flag asks whether the method, used as the *sole primary factor*,
    /// is worth as much as primary-plus-step-up. A printed code is not:
    /// whoever holds the paper holds the account.
    ///
    /// Used as a step-up it satisfies the tier through the ordinary step-up
    /// machinery, which is the point of the method and is unaffected by this.
    /// The distinction matters because "recovery codes are a second factor"
    /// is exactly the reasoning that would set this `true` and quietly let a
    /// code alone log somebody in.
    fn is_mfa_equivalent(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::state::{IDENTITY_ATTR_AUTH_TIME, IDENTITY_ATTR_STEP_UP_SATISFIED};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// A credential store that honours the atomicity `delete_credential`
    /// requires: the removal happens under one lock, so among concurrent
    /// callers naming the same id exactly one sees `true`.
    #[derive(Clone, Default)]
    struct TestStore {
        creds: Arc<Mutex<Vec<(String, String, serde_json::Value)>>>,
    }

    #[async_trait]
    impl CredentialStore for TestStore {
        async fn save_credential(
            &self,
            user_id: &str,
            cred_type: &str,
            data: serde_json::Value,
        ) -> Result<(), AuthError> {
            self.creds
                .lock()
                .unwrap()
                .push((user_id.to_string(), cred_type.to_string(), data));
            Ok(())
        }

        async fn get_credentials(
            &self,
            user_id: &str,
            cred_type: &str,
        ) -> Result<Vec<serde_json::Value>, AuthError> {
            Ok(self
                .creds
                .lock()
                .unwrap()
                .iter()
                .filter(|(u, t, _)| u == user_id && t == cred_type)
                .map(|(_, _, d)| d.clone())
                .collect())
        }

        async fn update_credential(
            &self,
            _credential_id: &str,
            _data: serde_json::Value,
        ) -> Result<(), AuthError> {
            Ok(())
        }

        async fn delete_credential(
            &self,
            user_id: &str,
            cred_type: &str,
            credential_id: &str,
        ) -> Result<bool, AuthError> {
            let mut creds = self.creds.lock().unwrap();
            let before = creds.len();
            creds.retain(|(u, t, d)| {
                !(u == user_id
                    && t == cred_type
                    && d.get("credential_id").and_then(|v| v.as_str()) == Some(credential_id))
            });
            Ok(creds.len() < before)
        }
    }

    fn method() -> RecoveryCodeAuthMethod<TestStore> {
        RecoveryCodeAuthMethod::new(TestStore::default())
    }

    /// An identity that authenticated just now, so a freshness gate passes.
    fn fresh(subject: &str) -> Identity {
        let mut attributes = HashMap::new();
        attributes.insert(
            IDENTITY_ATTR_AUTH_TIME.to_string(),
            chrono::Utc::now().timestamp().to_string(),
        );
        attributes.insert(
            IDENTITY_ATTR_STEP_UP_SATISFIED.to_string(),
            "true".to_string(),
        );
        Identity {
            provider_id: "test".to_string(),
            external_id: subject.to_string(),
            email: None,
            username: None,
            attributes,
        }
    }

    fn gate() -> ReproofRequirement {
        ReproofRequirement::new(300)
    }

    fn redeem(user_id: &str, code: &str) -> AuthInput {
        AuthInput::RecoveryCode {
            user_id: user_id.to_string(),
            code: code.to_string(),
        }
    }

    #[tokio::test]
    async fn a_generated_code_authenticates_its_account() {
        let m = method();
        let codes = m.generate(&fresh("alice"), &gate(), 10).await.unwrap();
        assert_eq!(codes.len(), 10);

        let identity = m.authenticate(redeem("alice", &codes[0])).await.unwrap();
        assert_eq!(identity.external_id, "alice");
        assert_eq!(identity.provider_id, METHOD_NAME_RECOVERY_CODE);
    }

    #[tokio::test]
    async fn each_code_works_exactly_once() {
        let m = method();
        let codes = m.generate(&fresh("alice"), &gate(), 5).await.unwrap();

        assert!(m.authenticate(redeem("alice", &codes[0])).await.is_ok());
        assert!(matches!(
            m.authenticate(redeem("alice", &codes[0])).await,
            Err(AuthError::InvalidCredentials)
        ));
        // The rest of the set is untouched.
        assert!(m.authenticate(redeem("alice", &codes[1])).await.is_ok());
    }

    /// The property that cost OTP a review round: single use must survive
    /// concurrency, not merely serial calls.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_redemptions_of_one_code_yield_one_identity() {
        let m = Arc::new(method());
        let codes = m.generate(&fresh("alice"), &gate(), 3).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = m.clone();
            let code = codes[0].clone();
            handles.push(tokio::spawn(async move {
                m.authenticate(redeem("alice", &code)).await.is_ok()
            }));
        }
        let mut accepted = 0;
        for h in handles {
            if h.await.unwrap() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 1, "one code was redeemed {accepted} times");
    }

    #[tokio::test]
    async fn a_code_is_not_valid_for_another_account() {
        let m = method();
        let alice = m.generate(&fresh("alice"), &gate(), 5).await.unwrap();
        m.generate(&fresh("bob"), &gate(), 5).await.unwrap();

        assert!(matches!(
            m.authenticate(redeem("bob", &alice[0])).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(m.authenticate(redeem("alice", &alice[0])).await.is_ok());
    }

    /// Codes are read off paper and retyped. Rejecting a correct one because
    /// the dashes or case differ would cause the failure this method exists
    /// to prevent.
    #[tokio::test]
    async fn separators_and_case_do_not_matter() {
        let m = method();
        let codes = m.generate(&fresh("alice"), &gate(), 3).await.unwrap();
        let mangled = codes[0].replace('-', "").to_lowercase();

        assert!(m.authenticate(redeem("alice", &mangled)).await.is_ok());
    }

    #[tokio::test]
    async fn regenerating_replaces_the_previous_set() {
        let m = method();
        let first = m.generate(&fresh("alice"), &gate(), 5).await.unwrap();
        let second = m.generate(&fresh("alice"), &gate(), 5).await.unwrap();

        assert_eq!(m.remaining(&fresh("alice")).await.unwrap(), 5);
        assert!(matches!(
            m.authenticate(redeem("alice", &first[0])).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(m.authenticate(redeem("alice", &second[0])).await.is_ok());
    }

    #[tokio::test]
    async fn generation_is_refused_without_a_fresh_enough_proof() {
        let m = method();
        let mut stale = fresh("alice");
        stale.attributes.insert(
            IDENTITY_ATTR_AUTH_TIME.to_string(),
            (chrono::Utc::now().timestamp() - 10_000).to_string(),
        );

        assert!(m.generate(&stale, &gate(), 5).await.is_err());
        // And nothing was written.
        assert_eq!(m.remaining(&fresh("alice")).await.unwrap(), 0);
    }

    /// RFC-012 §4.7: this drives `require_step_up`, so it has to mean "has a
    /// fallback that can still be used".
    #[tokio::test]
    async fn has_enrolled_tracks_unredeemed_codes_not_history() {
        let m = method();
        assert!(!m.has_enrolled("alice").await.unwrap());

        let codes = m.generate(&fresh("alice"), &gate(), 2).await.unwrap();
        assert!(m.has_enrolled("alice").await.unwrap());

        m.authenticate(redeem("alice", &codes[0])).await.unwrap();
        assert!(
            m.has_enrolled("alice").await.unwrap(),
            "one code left is still a fallback"
        );

        m.authenticate(redeem("alice", &codes[1])).await.unwrap();
        assert!(
            !m.has_enrolled("alice").await.unwrap(),
            "an exhausted set is not a fallback"
        );
    }

    #[tokio::test]
    async fn remaining_counts_down_as_codes_are_redeemed() {
        let m = method();
        let codes = m.generate(&fresh("alice"), &gate(), 4).await.unwrap();
        assert_eq!(m.remaining(&fresh("alice")).await.unwrap(), 4);

        m.authenticate(redeem("alice", &codes[0])).await.unwrap();
        assert_eq!(m.remaining(&fresh("alice")).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn an_empty_set_is_refused_rather_than_generated() {
        let m = method();
        assert!(matches!(
            m.generate(&fresh("alice"), &gate(), 0).await,
            Err(AuthError::InvalidInput)
        ));
    }

    #[tokio::test]
    async fn the_store_never_holds_a_code() {
        let store = TestStore::default();
        let m = RecoveryCodeAuthMethod::new(store.clone());
        let codes = m.generate(&fresh("alice"), &gate(), 3).await.unwrap();

        let held = serde_json::to_string(&*store.creds.lock().unwrap()).unwrap();
        for code in &codes {
            assert!(!held.contains(code), "a code reached the store verbatim");
            assert!(
                !held.contains(&normalise(code)),
                "a normalised code reached the store"
            );
        }
    }

    #[tokio::test]
    async fn recovery_codes_are_not_mfa_equivalent() {
        let m = method();
        assert!(!m.is_mfa_equivalent());
        assert_eq!(m.name(), "recovery-code");
    }

    #[test]
    fn codes_are_unique_and_shaped_for_typing() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2_000 {
            let code = generate_code();
            assert!(seen.insert(code.clone()), "duplicate code {code}");
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'),
                "{code}"
            );
            assert_eq!(normalise(&code).len(), 16, "{code}");
        }
    }
}
