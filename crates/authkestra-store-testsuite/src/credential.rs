//! Shared conformance suite for [`CredentialStore`].
//!
//! Every other atomicity promise in this workspace has a suite behind it —
//! `AtomicInsert`'s replay guard, `AtomicConsume`, `AtomicDecrement`'s retry
//! budget. `CredentialStore` had none, which mattered once
//! `delete_credential`'s `Ok(true)` became something callers are entitled to
//! treat as winning a race: a single-use credential is redeemed by looking it
//! up and accepting only if that call removed it.
//!
//! A store that implements deletion as "look it up, then delete it" satisfies
//! the signature, passes every serial test, and lets two concurrent
//! redemptions of the same credential both succeed. That is the defect this
//! suite exists to catch, and it is only visible under concurrency — which is
//! why [`run_credential_store_tests`] insists on a store it can clone into
//! several tasks.

use authkestra_engine::auth::store::CredentialStore;
use authkestra_engine::auth::AuthError;

const USER: &str = "conformance-user";
const OTHER_USER: &str = "somebody-else";
const CRED_TYPE: &str = "conformance-cred";
const OTHER_TYPE: &str = "other-cred";

fn credential(id: &str, payload: &str) -> serde_json::Value {
    serde_json::json!({ "credential_id": id, "payload": payload })
}

/// Runs the full suite.
///
/// `store_factory` must hand back a store with no credentials in it; each
/// case gets its own.
pub async fn run_credential_store_tests<S>(store_factory: &impl Fn() -> S)
where
    S: CredentialStore + Clone + Send + Sync + 'static,
{
    test_save_and_get_round_trip(store_factory()).await;
    test_get_filters_by_user_and_type(store_factory()).await;
    test_saving_the_same_id_replaces_rather_than_appends(store_factory()).await;
    test_delete_reports_whether_it_deleted(store_factory()).await;
    test_delete_credentials_reports_a_count(store_factory()).await;
    test_concurrent_deletes_of_one_credential_have_one_winner(store_factory()).await;
}

async fn test_save_and_get_round_trip<S: CredentialStore>(store: S) {
    assert!(
        store
            .get_credentials(USER, CRED_TYPE)
            .await
            .unwrap()
            .is_empty(),
        "a fresh store must start empty"
    );

    store
        .save_credential(USER, CRED_TYPE, credential("a", "one"))
        .await
        .unwrap();

    let held = store.get_credentials(USER, CRED_TYPE).await.unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0]["payload"], "one");
}

/// Credentials are scoped by both user and type. A store that ignored either
/// would hand one account another's factors.
async fn test_get_filters_by_user_and_type<S: CredentialStore>(store: S) {
    store
        .save_credential(USER, CRED_TYPE, credential("a", "mine"))
        .await
        .unwrap();
    store
        .save_credential(OTHER_USER, CRED_TYPE, credential("b", "theirs"))
        .await
        .unwrap();
    store
        .save_credential(USER, OTHER_TYPE, credential("c", "different kind"))
        .await
        .unwrap();

    let held = store.get_credentials(USER, CRED_TYPE).await.unwrap();
    assert_eq!(held.len(), 1, "got {held:?}");
    assert_eq!(held[0]["payload"], "mine");
}

/// `save_credential` documents this: a credential carrying an id that already
/// exists replaces it rather than landing beside it. TOTP re-enrolment relies
/// on it to rotate a secret without a window where the user has none — a
/// store that appended instead would keep serving the superseded secret.
async fn test_saving_the_same_id_replaces_rather_than_appends<S: CredentialStore>(store: S) {
    store
        .save_credential(USER, CRED_TYPE, credential("stable", "first"))
        .await
        .unwrap();
    store
        .save_credential(USER, CRED_TYPE, credential("stable", "second"))
        .await
        .unwrap();

    let held = store.get_credentials(USER, CRED_TYPE).await.unwrap();
    assert_eq!(held.len(), 1, "the id should have been replaced: {held:?}");
    assert_eq!(held[0]["payload"], "second");
}

async fn test_delete_reports_whether_it_deleted<S: CredentialStore>(store: S) {
    store
        .save_credential(USER, CRED_TYPE, credential("a", "one"))
        .await
        .unwrap();

    match store.delete_credential(USER, CRED_TYPE, "a").await {
        Err(AuthError::Unsupported) => return, // Deletion is optional.
        Ok(deleted) => assert!(
            deleted,
            "deleting a credential that exists must report true"
        ),
        Err(e) => panic!("unexpected error: {e}"),
    }

    assert!(store
        .get_credentials(USER, CRED_TYPE)
        .await
        .unwrap()
        .is_empty());

    assert!(
        !store.delete_credential(USER, CRED_TYPE, "a").await.unwrap(),
        "deleting a credential that is already gone must report false"
    );
    assert!(
        !store
            .delete_credential(USER, CRED_TYPE, "never-existed")
            .await
            .unwrap(),
        "deleting an unknown id must report false rather than erroring"
    );
}

async fn test_delete_credentials_reports_a_count<S: CredentialStore>(store: S) {
    for i in 0..3 {
        store
            .save_credential(USER, CRED_TYPE, credential(&format!("id-{i}"), "x"))
            .await
            .unwrap();
    }
    store
        .save_credential(USER, OTHER_TYPE, credential("keep", "x"))
        .await
        .unwrap();

    match store.delete_credentials(USER, CRED_TYPE).await {
        Err(AuthError::Unsupported) => return,
        Ok(n) => assert_eq!(n, 3, "should report how many it removed"),
        Err(e) => panic!("unexpected error: {e}"),
    }

    assert!(store
        .get_credentials(USER, CRED_TYPE)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store.get_credentials(USER, OTHER_TYPE).await.unwrap().len(),
        1,
        "deleting one type must leave the others alone"
    );
}

/// The case this suite was written for.
///
/// `delete_credential`'s `Ok(true)` means *this call* removed the credential,
/// so among concurrent callers naming the same id at most one may see it.
/// Callers redeeming a single-use credential treat that `true` as winning the
/// race; a store that checks and then deletes lets several of them win, and
/// the resulting double-redemption is invisible in every serial test above.
async fn test_concurrent_deletes_of_one_credential_have_one_winner<S>(store: S)
where
    S: CredentialStore + Clone + Send + Sync + 'static,
{
    store
        .save_credential(USER, CRED_TYPE, credential("contested", "one"))
        .await
        .unwrap();

    // Probe first: a store that does not implement deletion has nothing to
    // race, and must not be failed for it.
    match store
        .delete_credential(USER, CRED_TYPE, "probe-absent")
        .await
    {
        Err(AuthError::Unsupported) => return,
        Ok(_) => {}
        Err(e) => panic!("unexpected error: {e}"),
    }

    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            store
                .delete_credential(USER, CRED_TYPE, "contested")
                .await
                .unwrap()
        }));
    }

    let mut winners = 0;
    for h in handles {
        if h.await.unwrap() {
            winners += 1;
        }
    }

    assert_eq!(
        winners, 1,
        "exactly one concurrent delete may report true; {winners} did. A \
         credential redeemed once would have been accepted {winners} times."
    );
}
