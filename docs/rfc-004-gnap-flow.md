# RFC-004: GNAP (RFC 9635) Compatibility for the `Flow` Abstraction

## 1. Summary

This RFC analyses what `authkestra-engine`'s `Flow` / `FlowContext` /
`FlowResult` abstraction would need in order to express GNAP — the Grant
Negotiation and Authorization Protocol, published as **RFC 9635 (October
2024, Proposed Standard)** and informally called "OAuth 3.0" — alongside the
existing OAuth 2.0 flows.

It is a **design document only**: no code changes accompany it. It exists to
answer the roadmap Phase 1 item "Update `Flow` trait for GNAP compatibility"
(`docs/roadmap.md`) with a concrete proposal, and to give the follow-up
prototype ticket a plan it can start executing on day one.

The headline findings are:

1. **GNAP is stable enough to build against.** RFC 9635 and its companion
   RFC 9767 are both published Proposed Standards; the IETF GNAP working
   group has concluded. There is no moving draft to chase for the core
   protocol.
2. **The blast radius of changing `Flow` is far smaller than the ticket
   assumes.** `Flow` has exactly **one** production implementor in the
   workspace (`OAuth2Flow`) plus one test double. `DeviceFlow` and
   `ClientCredentialsFlow` do *not* implement `Flow` at all. See §4.1.
3. **The interesting design question is not "how do we widen `Flow`" but
   "should GNAP go through `Flow` at all".** GNAP's grant lifecycle is a
   server-side state machine with its own persistence and four HTTP verbs;
   `Flow` today is a stateless single-shot `execute`. §5 lays out both
   answers and §8 reserves the choice for the maintainer.

## 2. Specification status (what is stable, what is not)

Verified against the IETF Datatracker and the RFC Editor in September 2026:

| Document | Number | Date | Status |
| --- | --- | --- | --- |
| Grant Negotiation and Authorization Protocol (GNAP) | **RFC 9635** | October 2024 | Proposed Standard (IETF stream) |
| GNAP Resource Server Connections | **RFC 9767** | April 2025 | Proposed Standard (IETF stream) |
| `draft-ietf-gnap-core-protocol` | — | — | Superseded; published as RFC 9635 |
| `draft-ietf-gnap-resource-servers` | — | — | Superseded; published as RFC 9767 |

The **GNAP working group is concluded**. Everything this RFC proposes to
implement is drawn from RFC 9635 (client-facing AS behaviour). RFC 9767 is
cited only where it bears on the resource-server side
(`authkestra-resource`), which is explicitly out of scope here.

Two areas remain genuinely open-ended even within the published RFCs, and
implementations must make local choices:

- **Key proofing** (RFC 9635 §7.3) references external specifications —
  HTTP Message Signatures (`httpsig`), MTLS (`mtls`), detached JWS
  (`jwsd`), attached JWS (`jws`). New methods can be registered in the
  IANA "GNAP Key Proofing Methods" registry (§10.16), so the set is open by
  design.
- **Access rights** (RFC 9635 §8) deliberately leaves the internal structure
  of an `access` object to the API being protected; only `type` is required
  to be a string. GNAP does not standardise a `scope` equivalent, though
  Appendix B.5 shows how OAuth 2.0 scopes map onto it.

Anything not backed by a section citation below should be treated as this
RFC's opinion, not as protocol.

## 3. GNAP's model versus OAuth 2.0 redirect flows

### 3.1. One endpoint, JSON bodies, no form encoding

OAuth 2.0 spreads a flow across a browser-facing `/authorize` (GET, query
string) and a back-channel `/token` (POST,
`application/x-www-form-urlencoded`). GNAP has a **single grant endpoint**.
Every request to it is an HTTP POST whose content is a JSON object with
`Content-Type: application/json` (RFC 9635 §2). The top-level request
fields are `access_token`, `subject`, `client`, `user`, and `interact`
(§2.1–§2.5).

Practical consequence for Authkestra: the axum/actix adapters currently
extract OP requests with `Form<...>` and `Query<...>`
(`crates/authkestra-axum/src/op.rs:67`, `:118`). A GNAP endpoint needs
`Json<...>` extraction plus access to the raw request bytes, because key
proofing signs over the message content (§7.3).

### 3.2. A grant is a stateful, addressable resource

An OAuth 2.0 authorization code is a one-shot bearer string. A GNAP grant
request is a server-side object with an explicit state machine (§1.5):

```
                                                   .-----.
                                                  |       |
                                           +------+--+    | continue
                  .---need interaction---->|         |    |
                 /                         | pending |<--'
                /   .--finish interaction--+         |
               /   /    (approve/deny)     +----+----+
              /   /                             |
             /   /                              | cancel
            /   v                               v
         +-+----------+                   +===========+
         |            |                   |           |
---req-->| processing +------finalize---->| finalized |
         |            |                   |           |
         +-+----------+                   +===========+
            \    ^                              ^
             \    \                             | revoke or
              \    \                            | finalize
               \    \                     +-----+----+
                \    '-----update---------+          |
                 \                        | approved |<--.
                  '----no interaction---->|          |    |
                                          +-------+--+    | continue
                                                  |       |
                                                   '-----'
```

(Redrawn from RFC 9635 §1.5, Figure 2. Note the two `continue` self-loops —
polling or continuing a grant leaves it in the same state — the direct
_processing_ → _finalized_ edge taken on timeout or unrecoverable error, and
that _approved_ → _finalized_ happens on either revocation or normal
finalisation.)

The AS hands the client a `continue` object (§3.1) containing a `uri`, an
optional `wait` (seconds; absent means five, and SHOULD NOT be below five),
and a **continuation access token that MUST be key-bound and MUST NOT be a
bearer token**. The client then drives the grant with four verbs against
that URI:

| Verb | Section | Meaning |
| --- | --- | --- |
| `POST` with `{"interact_ref": ...}` | §5.1 | Continue after a completed interaction |
| `POST` with no content | §5.2 | Poll during pending interaction |
| `PATCH` | §5.3 | Modify an existing request (returns it to _processing_) |
| `DELETE` | §5.4 | Revoke the grant request |

Issued access tokens get their own management API (`manage.uri`, §3.2.1),
with `POST` to rotate (§6.1) and `DELETE` to revoke (§6.2).

### 3.3. Interaction is negotiated, not assumed

OAuth 2.0 hardcodes "redirect the browser". GNAP treats interaction as a
capability the *client* advertises and the AS selects from. The client sends
`interact.start` as an array of **start modes** (§2.5.1):

- `redirect` — client can send the end user to an arbitrary AS URI (§2.5.1.1)
- `app` — client can launch an application-specific URI (§2.5.1.2)
- `user_code` — client can display a short code for a *static* URI (§2.5.1.3)
- `user_code_uri` — short code plus a short *dynamic* URI (§2.5.1.4)

and optionally `interact.finish` (§2.5.2) with `method` (`redirect` or
`push`), `uri`, a client-generated `nonce` (REQUIRED), and `hash_method`
(**default `sha-256`**, from the IANA Named Information Hash Algorithm
Registry).

The AS answers with the corresponding interaction response (§3.3.1–§3.3.5),
including its own `finish` nonce (§3.3.5). When interaction concludes, the
AS delivers `interact_ref` and `hash` either by browser redirect (§4.2.1) or
by direct POST to the client (§4.2.2).

The `hash` (§4.2.3) is computed over a base string of exactly four values
joined by a single newline (`0x0A`), no trailing newline:

```
<client nonce from interact.finish (§2.5.2)>
<AS nonce from the finish response (§3.3.5)>
<interact_ref returned by the AS (§4.2)>
<the grant endpoint URI the client POSTed to (§2)>
```

hashed with `hash_method` and encoded URL-safe base64 **without padding**.
The AS MUST always provide it and the client MUST validate it.

Note the shape of `user_code` / `user_code_uri`: this is RFC 8628 device
flow, generalised. Authkestra already ships that machinery
(`crates/authkestra-op/src/handlers/device_authorization.rs`,
`device_verify.rs`, and `DeviceCodeStore`), which is the single largest
piece of reusable prior art for a GNAP prototype.

### 3.4. Multiple access tokens per grant

A client may request an **array** of access token objects, each carrying a
mandatory unique `label` (§2.1.2), and receive an array back keyed by those
labels (§3.2.2). Each returned token (§3.2.1) has `value`, `label`,
`access`, and optionally `manage`, `expires_in`, `key`, and `flags`. The
`bearer` flag's *absence* is what marks a token as key-bound — the default
in GNAP is the opposite of OAuth 2.0's.

### 3.5. Requests are key-bound from the first byte

There is no `client_id` + `client_secret`. The client instance is
identified by the key it signs with (§2.3): "If the same public key is sent
by value on different access requests, the AS MUST treat these requests as
coming from the same client instance." Every request is signed with one of
the §7.3 proofing methods, and access tokens are presented with the `GNAP`
HTTP authentication scheme (§7.2, registered in §10.1) rather than `Bearer`.

Authkestra has adjacent primitives but not this one: DPoP proof
verification (`crates/authkestra-engine/src/token/dpop.rs`), JWK thumbprints
(`dpop.rs:313`), mTLS certificate binding
(`crates/authkestra-engine/src/token/cert_binding.rs`), and `private_key_jwt`
client assertions (`crates/authkestra-engine/src/client_assertion.rs`).
There is **no** RFC 9421 HTTP Message Signatures implementation anywhere in
the workspace or its dependency graph — `httpsig`, the method GNAP examples
use throughout, would be new work.

## 4. Gap analysis

### 4.1. What exists today

All three types live in one file, `crates/authkestra-engine/src/flow/mod.rs`:

- **`FlowContext`** — `mod.rs:24-31`. `#[non_exhaustive]`, derives
  `Debug, Clone, Serialize, Deserialize`. Two fields: `state: String` and
  `params: HashMap<String, String>`.
- **`FlowResult`** — `mod.rs:34-42`. Derives
  `Debug, Clone, Serialize, Deserialize`. Three variants:
  `Complete(Identity)`, `Redirect(String)`, `Pending`. **Not**
  `#[non_exhaustive]`.
- **`Flow`** — `mod.rs:45-52`. `#[async_trait]`, `Send + Sync`, two methods:
  `fn id(&self) -> &str` and
  `async fn execute(&self, ctx: FlowContext) -> Result<FlowResult, AuthError>`.

Implementors in the entire workspace:

| Implementor | Location | Notes |
| --- | --- | --- |
| `OAuth2Flow<P, M>` | `crates/authkestra-engine/src/flow/oauth2.rs:17-46` | The callback branch is a stub that returns `AuthError::Token("Direct Flow execution not updated for encrypted state")` (`oauth2.rs:29-31`) |
| `MockFlow` | `crates/authkestra-engine/src/tests.rs:41-54` | Test double |

`DeviceFlow` (`crates/authkestra-engine/src/flow/device_flow.rs:32`) and
`ClientCredentialsFlow`
(`crates/authkestra-engine/src/flow/client_credentials_flow.rs:37`) are
plain structs with inherent async methods. **Neither implements `Flow`.**
Any statement of the form "this change breaks Device / ClientCredentials
implementors" is therefore vacuous today, and this RFC does not make it.

`Engine` does not hold a `Flow` registry either: it stores
`HashMap<String, Arc<dyn ErasedOAuthFlow>>`
(`crates/authkestra-engine/src/engine.rs:49`). Nothing in `authkestra-op`,
`authkestra-axum`, or `authkestra-actix` mentions `Flow`, `FlowContext`, or
`FlowResult`. **The `Flow` trait is currently unwired**: no request path in
the workspace dispatches through it.

That is the most important input to the decision in §5 — the cost of a
breaking change to `Flow` is close to zero *right now*, and will only grow.

### 4.2. What GNAP needs that the current types cannot express

| # | GNAP requirement | Section | Why the current types can't carry it |
| --- | --- | --- | --- |
| G1 | Request body is an arbitrarily nested JSON object (`access_token.access[]`, `client.key.jwk`, `interact.start[]`) | §2 | `FlowContext.params` is `HashMap<String, String>` (`mod.rs:30`). Flattening `access[]` into string keys loses arrays and objects and has no round-trip. |
| G2 | Response is a JSON object that may carry `continue` + `interact` + `access_token` + `subject` *simultaneously* | §3 | `FlowResult` (`mod.rs:35-42`) is a three-way choice. `Redirect(String)` cannot also carry a continuation token; `Pending` carries nothing at all — not the `continue.uri`, not `wait`, not the continuation access token. |
| G3 | Grant identity is a server-side record with a lifecycle (`processing`/`pending`/`approved`/`finalized`) that survives across four separate HTTP requests | §1.5, §5 | `Flow::execute` (`mod.rs:51`) is a single-shot `&self` call with no store handle and no notion of resuming a prior grant. `FlowContext.state: String` is a CSRF nonce, not a grant handle. |
| G4 | Four verbs (`POST`/`POST`-poll/`PATCH`/`DELETE`) against one continuation URI, plus `POST`/`DELETE` on each token's `manage.uri` | §5.1–§5.4, §6.1–§6.2 | The trait has exactly one method. There is no way to express "which operation is this". |
| G5 | Every request carries a key proof over method, URI, headers and body | §7.3 | `FlowContext` has no request metadata at all — no method, no URI, no headers, no raw body. It also cannot gain them cheaply: it derives `Serialize`/`Deserialize` (`mod.rs:24`), and `http::HeaderMap` is not `Serialize`. |
| G6 | Multiple labelled access tokens, key-bound by default, each with a `manage` URI | §2.1.2, §3.2.2 | `FlowResult::Complete(Identity)` returns an `Identity` (`crates/authkestra-engine/src/auth/state.rs:7-18`) and no tokens. The nearest token type, `OAuthToken` (`state.rs:49-66`), is a single token with a string `scope`, no `label`, no `manage`, and no key binding field. |
| G7 | Subject information returned as `sub_ids` (typed identifier formats) and `assertion_formats` | §2.2, §3.4 | `Identity` (`state.rs:7-18`) has `provider_id`/`external_id`/`email`/`username` plus `attributes: HashMap<String, String>`. Typed subject identifiers would have to be stringly encoded into `attributes`. |
| G8 | Structured protocol errors with a registered `code` and optional `description` (`user_denied`, `too_fast`, `too_many_attempts`, `invalid_continuation`, …) | §3.6, §10.15 | `AuthError` (`crates/authkestra-engine/src/auth/error.rs:5-42`) has no variant carrying a protocol error code; the nearest is `Provider(String)`/`Token(String)`. GNAP error codes must round-trip verbatim into the JSON response. |
| G9 | Interaction hash validation over four newline-joined values | §4.2.3 | Not expressible — nothing in `FlowContext`/`FlowResult` holds the AS nonce, the client nonce, or the grant endpoint URI together. |

### 4.3. Two incidental defects found while reading

Neither is caused by GNAP; both should be fixed by whoever touches this
file next, and both are cited here because they change what "least
breaking" means.

- **`FlowContext` is unconstructable outside `authkestra-engine`.** It is
  `#[non_exhaustive]` (`mod.rs:25`) with no constructor and no `Default`.
  The only construction site is the crate's own test
  (`crates/authkestra-engine/src/tests.rs:89`). An external crate cannot
  implement a useful `Flow` today because it cannot build the input to
  `execute` for its own tests, and `Engine` never builds one for it either.
  Adding fields to `FlowContext` is consequently *not* a downstream
  breaking change — nobody downstream can name them.
- **`FlowResult` is not `#[non_exhaustive]`** (`mod.rs:34-35`), unlike its
  sibling. Adding a variant is a breaking change for any downstream
  exhaustive `match`. Marking it `#[non_exhaustive]` is itself the breaking
  change, and is cheapest to make now.
- Stale docs: `docs/book/ch03-core-traits.md:59` still names the method
  `next_step`, and `docs/rfc-001-architecture-migration.md:82-86` shows
  `Flow` without the `id` method or the `Send + Sync` bound. Per AGENTS.md
  ("Docs Are Not Compiled"), whichever PR changes the trait must update
  both.

## 5. Proposed changes

Two routes. They are not mutually exclusive in the long run — Route A can
be adopted first and Route B layered on later — but the prototype should
pick one, and which one is a maintainer decision (§8, Q1).

### Route A — GNAP does not go through `Flow` (least breaking)

`Flow` stays exactly as it is. GNAP is modelled as its own trait in
`authkestra-op`, because a GNAP AS is server-side protocol handling, which
is what `authkestra-op` already is — mirroring how `handle_authorize` /
`handle_token` are *not* `Flow` implementors either.

```rust
// crates/authkestra-op/src/gnap/mod.rs  (illustrative only)

/// The four continuation verbs of RFC 9635 §5 plus the initial request of §2.
#[non_exhaustive]
pub enum GrantOperation {
    /// POST to the grant endpoint (§2).
    Request(GrantRequest),
    /// POST to `continue.uri` with `interact_ref` (§5.1).
    ContinueAfterInteraction { interact_ref: String },
    /// POST to `continue.uri` with no content (§5.2).
    Poll,
    /// PATCH `continue.uri` (§5.3).
    Modify(GrantRequest),
    /// DELETE `continue.uri` (§5.4).
    Revoke,
}

/// Everything a key proof (§7.3) has to be checked against, kept out of
/// `GrantRequest` because it is transport metadata, not protocol content.
#[non_exhaustive]
pub struct ProofContext<'a> {
    pub method: &'a http::Method,
    pub uri: &'a http::Uri,
    pub headers: &'a http::HeaderMap,
    /// The exact bytes received, before deserialisation — `httpsig`,
    /// `jwsd` and `jws` all sign over these.
    pub body: &'a [u8],
}

#[async_trait]
pub trait GnapAuthorizationServer: Send + Sync {
    async fn handle(
        &self,
        op: GrantOperation,
        proof: ProofContext<'_>,
        store: &dyn GnapGrantStore,
    ) -> Result<GrantResponse, GnapError>;
}
```

**Breaking for existing implementors: no.** Nothing about `Flow`,
`FlowContext`, `FlowResult`, `OAuth2Flow`, `DeviceFlow`,
`ClientCredentialsFlow`, `Engine`, or the adapters changes.

**New dependency required.** `ProofContext` above names `http::Method`,
`http::Uri` and `http::HeaderMap`, and `authkestra-op` has **no direct
`http` dependency** today — it only sees the crate transitively. Route A
therefore adds `http = "1"` to `crates/authkestra-op/Cargo.toml`, matching
the pin `authkestra-engine` already uses. This is additive and breaks no
implementor, but it is a new direct dependency and so needs a
`cargo deny check` pass (AGENTS.md, Pull Request Checks). Route B does not
incur it: `RequestParts` lives in `authkestra-engine`, which already
depends on `http = "1"`. The alternative — borrowing `&str` and
`&[(&str, &str)]` instead of the `http` types — avoids the dependency at
the cost of re-deriving values the adapters already hold parsed, and is
not recommended.

Cost: GNAP and OAuth2 do not share an abstraction, so a future "run any
protocol through one pipeline" story (middleware, tracing, rate limiting)
has to be built twice or retrofitted later.

### Route B — widen `Flow` so GNAP is a `Flow`

```rust
// crates/authkestra-engine/src/flow/mod.rs  (illustrative only)

/// Transport-level facts about the inbound request. Deliberately NOT part
/// of `FlowContext`: `FlowContext` derives `Serialize`/`Deserialize`
/// (mod.rs:24) and `http::HeaderMap` is not `Serialize`.
#[non_exhaustive]
pub struct RequestParts<'a> {
    pub method: &'a http::Method,
    pub uri: &'a http::Uri,
    pub headers: &'a http::HeaderMap,
    pub body: &'a [u8],
}

#[non_exhaustive]
pub struct FlowContext {
    pub state: String,
    pub params: HashMap<String, String>,
    /// The JSON body of a protocol that speaks JSON (GNAP, §2). `None`
    /// for the form-encoded OAuth 2.0 flows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

#[non_exhaustive]
pub enum FlowResult {
    Complete(Identity),
    Redirect(String),
    Pending,
    /// A protocol response that is a document rather than a redirect or an
    /// identity — a GNAP grant response (§3) carrying any combination of
    /// `continue`, `interact`, `access_token` and `subject`.
    Document(serde_json::Value),
}

#[async_trait]
pub trait Flow: Send + Sync {
    fn id(&self) -> &str;

    async fn execute(&self, ctx: FlowContext) -> Result<FlowResult, AuthError>;

    /// Protocols that must see the raw request (key proofing, §7.3)
    /// override this. The default delegates to `execute`, so every
    /// existing implementor keeps compiling unchanged.
    async fn execute_with_parts(
        &self,
        ctx: FlowContext,
        _parts: RequestParts<'_>,
    ) -> Result<FlowResult, AuthError> {
        self.execute(ctx).await
    }
}
```

Breaking-change assessment, item by item:

| Change | Breaking? | Least-breaking alternative |
| --- | --- | --- |
| New defaulted `Flow::execute_with_parts` | **No.** `OAuth2Flow` and `MockFlow` compile unchanged. Same technique already used in this codebase for `OpStore::handle_custom_grant` (`crates/authkestra-op/src/store.rs:65`) and `record_client_assertion_jti` (`:33`). | — |
| New `body` field on `FlowContext` | **No** for downstream — it is already `#[non_exhaustive]` (`mod.rs:25`) and unconstructable outside the crate (§4.3). Breaks the in-crate construction at `tests.rs:89`. | Ship a `FlowContext::new(state, params)` constructor in the same PR so the type becomes usable downstream at all. |
| New `FlowResult::Document` variant | **Yes, today.** `FlowResult` is not `#[non_exhaustive]` (`mod.rs:34`); any exhaustive downstream `match` stops compiling. | Add `#[non_exhaustive]` to `FlowResult` **first**, as its own PR, so this is a one-time break rather than a break per future variant. That first PR is itself breaking for exhaustive matches, so it belongs in the same minor release as the variant. |
| Changing `execute`'s signature outright (e.g. to take `RequestParts`) | **Yes**, for `OAuth2Flow` (`oauth2.rs:22`) and `MockFlow` (`tests.rs:45`) — the only two implementors. | Don't. The defaulted-method form above buys the same capability for free. |

Note that `serde_json::Value` for `body` and `Document` is a deliberate
trade: it keeps `FlowContext`/`FlowResult` `Serialize + Deserialize` (which
`Box<dyn Any>` would not), at the cost of losing static typing at the trait
boundary. A `GnapFlow` would deserialise into its own strongly-typed
`GrantRequest` immediately on entry. If the maintainer prefers static
typing at the boundary, the alternative is generic associated types on
`Flow`, which conflicts with AGENTS.md's "prefer `Box<dyn Trait>` over
generics for I/O bound paths" and would be a hard break. Flagged as Q2.

### 5.1. Supporting types either route needs

These are new types, not modifications, so they are non-breaking under
either route.

```rust
/// RFC 9635 §1.5 grant states. The AS owns this; the client only observes it.
#[non_exhaustive]
pub enum GrantState { Processing, Pending, Approved, Finalized }

/// RFC 9635 §3.1.
pub struct ContinueResponse {
    pub uri: String,
    /// §3.1: omission MUST be read as 5; SHOULD NOT be below 5.
    pub wait: Option<u32>,
    /// §3.1: MUST be key-bound, MUST NOT be a bearer token.
    pub access_token: GnapAccessToken,
}

/// RFC 9635 §3.2.1. Distinct from `auth::state::OAuthToken` (state.rs:49):
/// GNAP tokens are labelled, key-bound by default, and self-managing.
pub struct GnapAccessToken {
    pub value: String,
    pub label: Option<String>,
    pub access: Vec<serde_json::Value>,   // §8: structure is API-defined
    pub manage: Option<TokenManagement>,  // §3.2.1 / §6
    pub expires_in: Option<u64>,
    pub key: Option<GnapKey>,             // §7.1
    /// §3.2.1: presence of "bearer" means NOT key-bound. Absence is the
    /// secure default — the inverse of OAuth 2.0.
    pub flags: Vec<String>,
}

/// RFC 9635 §7.3.
#[non_exhaustive]
pub enum KeyProof {
    /// §7.3.1. Requires RFC 9421 HTTP Message Signatures — not present in
    /// this workspace today (§3.5).
    HttpSig { alg: Option<String>, content_digest_alg: Option<String> },
    /// §7.3.2. `token::cert_binding` is adjacent prior art.
    Mtls,
    /// §7.3.3, media type `application/gnap-binding-jwsd` (§10.2.1).
    Jwsd,
    /// §7.3.4, media type `application/gnap-binding-jws` (§10.2.2).
    Jws,
}

/// RFC 9635 §3.6 / §10.15. Codes must round-trip verbatim.
pub struct GnapError {
    pub code: String,
    pub description: Option<String>,
}
```

`AuthError` (`crates/authkestra-engine/src/auth/error.rs:5-42`) would gain
one additive variant to carry `GnapError` (G8). Adding a variant to
`AuthError` is breaking for downstream exhaustive matches for the same
reason as `FlowResult`; `AuthError` is likewise not `#[non_exhaustive]`
today, and the same one-time-break remedy applies.

## 6. Staged plan for the feature-flagged prototype

This is the plan for the **fourth** checklist item of issue #41, which this
RFC deliberately does not implement.

### 6.1. Placement and feature name

**This plan is written in Route A's shape (§5) as a non-blocking default —
not as an answer to Q1.** Route A is picked for the prototype solely
because it is the non-breaking option: it adds new types in
`authkestra-op` and touches nothing that already exists, so building it
commits the project to nothing. If the maintainer later chooses Route B,
the same `GrantOperation` / `GrantResponse` / `GnapGrantStore` types are
layered *under* a `Flow` implementation rather than rewritten — the GNAP
protocol logic is identical either way, and only the trait it is reached
through differs. **Q1 remains the maintainer's call** (§8). Stages G0–G5
below are unaffected by the answer; only **G6** depends on it.

- **Crate**: `authkestra-op`, new module `src/gnap/`. Rationale: `Op` is
  already "Authkestra as an authorization server", already owns
  `ClientStore`/`DeviceCodeStore`/`OpStore`, and already has both adapters
  wired. Putting GNAP in `authkestra-engine` would drag a second protocol
  server into the crate that is supposed to be protocol-agnostic plumbing.
- **Feature name**: `gnap`, off by default, in `authkestra-op`,
  `authkestra-axum`, `authkestra-actix`, and the `authkestra` facade —
  matching the existing per-capability naming (`session`, `token`,
  `webauthn`, `totp`, `captcha`). Adapter features forward:
  `gnap = ["authkestra-op/gnap"]`. The facade's `full` feature should
  **not** include `gnap` while it is experimental.
- Every public item behind the flag carries a doc-comment stating that it
  tracks RFC 9635 and is unstable.

### 6.2. Endpoints

Two routes, wired in **both** `crates/authkestra-axum/src/op.rs` and
`crates/authkestra-actix/src/op.rs` in the same PR (AGENTS.md, DoD —
Framework Wiring):

| Route | Verbs | Section |
| --- | --- | --- |
| `/gnap` (grant endpoint) | `POST`, `OPTIONS` (discovery) | §2, §9 |
| `/gnap/continue/{id}` | `POST`, `PATCH`, `DELETE` | §5.1–§5.4 |

`OPTIONS /gnap` returns the §9 discovery document
(`grant_request_endpoint`, `interaction_start_modes_supported`,
`interaction_finish_methods_supported`, `key_proofs_supported`,
`key_rotation_supported`, …). It is the cheapest possible first endpoint —
no request parsing, no state — and is a good G0.

`/gnap/token/{id}` (token management, §6) is **out of scope for the
prototype**; the prototype omits `manage` from issued tokens, which §3.2.1
permits (`manage` is OPTIONAL).

### 6.3. Stages

- **G0 — skeleton + discovery.** `gnap` feature, `src/gnap/mod.rs`, the
  §2/§3 request and response types with serde round-trip tests against the
  literal JSON examples in RFC 9635 Appendix B, and `OPTIONS /gnap`. No
  state, no crypto.
- **G1 — `GnapGrantStore` trait + in-memory impl.** Mirrors the existing
  store pattern (`OpStore` supertraits, `crates/authkestra-op/src/store.rs`).
  Must persist: grant id, `GrantState`, client key, requested `access`,
  the client's `finish` nonce, the AS's own nonce, and `interact_ref`.
  Continuation-token lookup and single-use `interact_ref` consumption must
  be **atomic**, for the same reason
  `AuthorizationCodeStore::consume_code` is (RFC-003 §6): §5.1 requires a
  `too_many_attempts` error and finalisation if an `interact_ref` is
  replayed.
- **G2 — software-only grant (no interaction).** RFC 9635 §1.6.5 /
  Appendix B.3: `POST /gnap` with `client.key`, no `interact`, straight to
  _approved_, single access token issued via the existing `TokenManager`.
  This is the smallest end-to-end path and exercises G1–G6 of §4.2 without
  any interaction machinery. It is also the first stage with something
  runnable to show, so it carries the **facade example** required by
  AGENTS.md ("Examples Live in the Facade"): `axum_gnap_grant.rs` in
  `crates/authkestra/examples/`, declared with
  `required-features = ["gnap"]` and run as
  `cargo run -p authkestra --example axum_gnap_grant --all-features`,
  mirroring the existing `axum_op_server.rs`. One example is the budget —
  RFC-003 §9 spent the same on the entire OP — and an
  `actix_gnap_grant.rs` counterpart is deferred until the feature
  stabilises. The actix *routes* are still wired in the same PR, per the
  AGENTS.md Framework Wiring DoD; it is only the example that waits.
- **G3 — `user_code` interaction + polling.** Reuses the existing device
  flow verification handler and `DeviceCodeStore` shape
  (`crates/authkestra-op/src/handlers/device_verify.rs`). Covers §2.5.1.3,
  §3.3.3, §4.1.2, §5.2, and the `wait` / `too_fast` semantics.
- **G4 — `redirect` start + `redirect` finish.** Covers §2.5.1.1, §3.3.1,
  §4.1.1, §4.2.1, §5.1, and the §4.2.3 interaction hash.
- **G5 — multiple labelled access tokens.** §2.1.2 / §3.2.2.
- **G6 — decide `Flow` integration.** Only after G2–G5 exist, revisit §5
  Route A vs Route B with a working implementation in hand rather than a
  sketch. This RFC's recommendation is to defer the trait change to this
  point.

### 6.4. What to stub in the prototype

Stubbing these is what keeps the prototype small enough to be honest:

- **Key proofing (§7.3).** *Recommended* prototype stub, **pending the
  maintainer's answer to Q5** (§8): implement `jwsd` only, reject
  `httpsig`, `mtls` and `jws` with `invalid_request`, and advertise only
  `jwsd` in the §9 discovery document. The recommendation rests purely on
  proximity to code that already exists — `jwsd` is closest to the DPoP
  verification in `crates/authkestra-engine/src/token/dpop.rs`, whereas
  `httpsig` needs an RFC 9421 implementation that is nowhere in this
  workspace (§3.5). **Shipping `jwsd` first does not answer the strategic
  question.** GNAP's own examples and interop profiles centre on
  `httpsig`, and if the maintainer decides `httpsig` is what Authkestra
  should lead with, `jwsd` becomes throwaway scaffolding and this stub
  should be revisited before G2 rather than after. Because the §9
  discovery document advertises only what is actually verifiable, swapping
  the method later is a contained code change; committing to it in a
  release note or public documentation is not.
- **Token management API (§6).** Omit `manage` entirely.
- **Request modification (§5.3, `PATCH`).** Return `invalid_continuation`.
- **Subject information (§2.2 / §3.4).** Support only
  `sub_id_formats: ["opaque"]`; reject `assertion_formats`.
- **User identification (§2.4)** and **client-by-reference (§2.3.1).**
  Reject; require the key by value.
- **RFC 9767 (RS-facing API, introspection, resource registration).**
  Entirely out of scope.

### 6.5. What to test

Per AGENTS.md, CI runs `cargo test --workspace --all-features` and
`cargo llvm-cov --fail-under-lines 85`, so `--all-features` will compile
and exercise the `gnap` feature from the first PR.

- Serde round-trip tests against every JSON example in RFC 9635 Appendix B
  that the prototype claims to support. These are the cheapest possible
  conformance evidence and they catch field-name typos.
- **Interaction hash (§4.2.3) as a known-answer test.** The RFC supplies a
  worked example: the four-line base string
  `VJLO6A4CATR0KRO` / `MBDOFXG4Y5CVJCX821LH` / `4IFWWIKYB2PQ6U56NL1` /
  `https://server.example.com/tx` hashes under `sha-256` to
  `x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY`. Assert exactly that. It
  pins the newline separator, the absence of a trailing newline, the
  default algorithm, and unpadded URL-safe base64 in one test.
- A negative test that a replayed `interact_ref` yields
  `too_many_attempts` **and** moves the grant to _finalized_ (§5.1).
- A negative test that the continuation access token is rejected when
  presented without a key proof, and that it is never issued with the
  `bearer` flag (§3.1).
- A test that polling faster than `wait` yields `too_fast` (§3.6).
- Adapter-level tests for both axum and actix, since the DoD requires both
  to be wired.

## 7. Security notes

- **Fail closed on unknown proofing methods.** An AS that accepts a request
  whose `proof` it does not understand has no client authentication at all.
  The prototype must reject anything outside its advertised list, and the
  §9 discovery document must not advertise a method it cannot verify.
- **Never issue a bearer continuation token.** §3.1 makes this a MUST NOT,
  and it is easy to violate by reusing the existing OAuth token-issuing
  path unchanged.
- **`interact_ref` is single-use** (§4.2.1). Enforce atomically at the
  store layer, not in the handler.
- **The interaction hash is mandatory in both directions** (§4.2.3): the AS
  MUST send it, the client MUST validate it. Skipping it reopens the
  session-fixation and injection attacks of §11.25.
- **Callback URIs are attacker-influenced** (§11.18, §11.29, §11.34). The
  `push` finish method has the AS make an outbound HTTP request to a
  client-supplied URI — a textbook SSRF sink. If `push` is implemented at
  all, it needs an allowlist; the prototype should default to `redirect`
  only.
- **Grant continuation is a DoS surface** (§11.27). Grants need a TTL and
  a bounded number of continuation attempts.

## 8. Open questions — reserved for the maintainer

These are deliberately left unanswered. Each one is a judgement call about
the project's direction rather than a detail derivable from the RFC.

- **Q1. Route A or Route B (§5)?** Should GNAP be a `Flow`, or its own
  trait in `authkestra-op`? The roadmap item is phrased as "update the
  `Flow` trait", but the gap analysis (§4.1) shows `Flow` is currently
  unwired and GNAP's shape (stateful, multi-verb, key-proofed) is a poor
  fit for a single-shot `execute`. This RFC presents both and recommends
  deciding after the prototype (§6.3, G6) — but the choice is the
  maintainer's.
- **Q2. Is `serde_json::Value` acceptable at the `Flow` boundary?** Route B
  keeps `FlowContext`/`FlowResult` serialisable by carrying untyped JSON.
  The typed alternative needs generics on `Flow`, which cuts against
  AGENTS.md's trait-object guidance. Which trade wins?
- **Q3. Should `FlowResult` and `AuthError` be marked `#[non_exhaustive]`
  now?** It is a one-time breaking change that makes every future variant
  non-breaking. Doing it in a release that is already breaking is cheapest;
  doing it later costs the same break again.
- **Q4. Is `Flow` worth keeping at all?** `OAuth2Flow::execute`'s callback
  branch has been a stub returning an error since the stateless-cookie
  migration (`oauth2.rs:29-31`), `DeviceFlow` and `ClientCredentialsFlow`
  never adopted the trait, and `Engine` dispatches through
  `ErasedOAuthFlow` instead (`engine.rs:49`). Removing `Flow` is a live
  option that would make this whole RFC moot; it is not this RFC's call to
  make.
- **Q5. Which key proofing method is the strategic one?** The prototype
  proposes `jwsd` because it is closest to the existing DPoP code (§6.4),
  but GNAP's examples and most interop profiles centre on `httpsig`
  (RFC 9421), which would be a new dependency or a new implementation.
  Does `httpsig` get its own ticket, and at what priority?
- **Q6. Does `authkestra-resource` take on RFC 9767?** GNAP's RS-facing
  API (introspection at §3.3, resource registration at §3.4, the
  `/.well-known/gnap-as-rs` document at §3.1) is a separate body of work
  with its own value. In or out of the GNAP epic?
- **Q7. Does the facade's `full` feature ever include `gnap`?** §6.1
  proposes it should not while the implementation is experimental, which
  means `cargo test --workspace --all-features` covers it but a `full`
  build does not.

## 9. Non-goals

- Client-side GNAP (Authkestra acting as a GNAP client instance).
- A complete GNAP AS. §6.4 lists what the prototype deliberately stubs.
- RFC 9767 resource-server connections (see Q6).
- Any change to OAuth 2.0 / OIDC behaviour. RFC-003 remains the OP's
  specification, and GNAP runs alongside it rather than replacing it.

## 10. References

- [RFC 9635](https://www.rfc-editor.org/rfc/rfc9635.html) — Grant
  Negotiation and Authorization Protocol (GNAP), October 2024, Proposed
  Standard.
- [RFC 9767](https://www.rfc-editor.org/rfc/rfc9767.html) — GNAP Resource
  Server Connections, April 2025, Proposed Standard.
- [IETF GNAP working group](https://datatracker.ietf.org/group/gnap/) —
  concluded; both documents published.
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) — HTTP Message
  Signatures, the basis of GNAP's `httpsig` proofing method.
- `docs/rfc-001-architecture-migration.md` §4.3 — the original `Flow`
  sketch (now stale; see §4.3 above).
- `docs/rfc-003-oidc-provider.md` — the OP design this RFC runs alongside.
- `docs/roadmap.md` Phase 1 — the roadmap item this RFC answers.
