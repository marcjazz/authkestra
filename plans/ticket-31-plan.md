# Plan: Implement DPoP and full OAuth 2.1 compliance

This plan outlines the steps required to achieve full OAuth 2.1 compliance, focusing on DPoP and robust security measures.

## Goals

- Implement DPoP (RFC 9449) for sender-constrained tokens.
- Enhance nonce handling to prevent replay attacks in OIDC/OAuth 2.1.
- Enforce PKCE for all authorization code flows.
- Ensure deprecation of insecure grant types.

## Tasks

- [ ] **Task 1: DPoP Implementation**
  - [ ] Define DPoP proof validation logic.
  - [ ] Update `TokenResponse` to include DPoP-bound tokens.
  - [ ] Implement JWK thumbprint binding for access tokens.
- [ ] **Task 2: Robust Nonce Handling**
  - [ ] Implement nonce storage in encrypted cookies (as per AGENTS.md).
  - [ ] Add nonce validation to the `OAuth2Flow` and `OidcProvider`.
- [ ] **Task 3: OAuth 2.1 Enforcement**
  - [ ] Make PKCE mandatory in `authkestra-engine`.
  - [ ] Remove/Disable support for implicit and resource owner password credentials grants.
- [ ] **Task 4: Resource Indicators**
  - [ ] Support the `resource` parameter in authorization and token requests.

## Acceptance Criteria

- [ ] DPoP proofs are correctly validated at the token endpoint.
- [ ] Access tokens are bound to the public key provided in the DPoP header.
- [ ] Nonce validation fails if the nonce is missing or mismatched in OIDC flows.
- [ ] Authorization requests without PKCE are rejected.
- [ ] No support for implicit or password grants in the codebase.

## Definition of Done (DoD)

- [ ] All unit and integration tests pass for new features.
- [ ] Security audit of the new compliance features performed.
- [ ] Documentation updated in `docs/book`.
- [ ] Example apps updated to demonstrate DPoP usage.
