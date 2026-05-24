# Chapter 4: Flows and Protocols

Authentication and delegation in the 2020s require more than just simple redirects. Authkestra implements protocols that are secure-by-default and optimized for the autonomous machine economy.

## 1. OAuth 2.1: The Modern Baseline
Authkestra strictly adheres to the **OAuth 2.1** consolidation.
- **Mandatory PKCE**: Proof Key for Code Exchange is required for all flows.
- **No Implicit Grant**: Legacy insecure flows are deprecated.
- **Sender-Constraint**: Native support for **DPoP** (Demonstrating Proof-of-Possession) ensuring tokens cannot be replayed if stolen.

## 2. GNAP (Grant Negotiation and Authorization Protocol)
The **GNAP (RFC 9635)** implementation in `authkestra-engine` represents the future of delegation.
- **Intent-Driven**: Clients negotiate specific access rights in a single JSON request.
- **Dynamic Client Instances**: No more static `client_id` bottlenecks. Software instances negotiate keys on-the-fly.
- **Decoupled Interaction**: Support for multiple interaction modes, including QR codes, device codes, and app-to-app redirects.

## 3. Verifiable Presentations (OIDC4VP)
As users transition to digital wallets (e.g., the EUDI Wallet), Authkestra provides the infrastructure to act as a **Verifier**.
- **OIDC4VP Support**: Requesting verifiable credentials directly within an OpenID Connect flow.
- **Privacy-Preserving Proofs**: Support for validating **BBS+** signatures and **SD-JWTs**, allowing for selective disclosure without tracking.

## 4. WebAuthn & PQC
Our WebAuthn implementation is being upgraded to handle **Post-Quantum Cryptography**.
- **ML-DSA Support**: Preparing for the day when classical ECC and RSA are broken by quantum computers.
- **Fragmented Payloads**: Specialized transport handling to manage the multi-kilobyte PQC signatures that exceed standard CTAP-HID limits.
