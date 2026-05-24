# Chapter 9: Security & Threat Model

Authkestra is designed to resist the security challenges of the next decade, including the threat of quantum computing and the limitations of point-in-time authentication.

## 1. Quantum Resilience (PQC)
We are transitioning our cryptographic foundation to **Post-Quantum Cryptography** to mitigate "harvest now, decrypt later" attacks.
- **ML-DSA (FIPS 204)**: Our primary signature algorithm for tokens and internal credentials.
- **SLH-DSA (FIPS 205)**: Used as a stateless, hash-based backup for high-security environments.

## 2. Continuous Session Security (CAEP)
Legacy bearer tokens are a significant vulnerability. Authkestra mitigates this by shifting to **Continuous Access Evaluation**.
- **SSF Event Stream**: We integrate with the Shared Signals Framework to receive real-time risk telemetry.
- **Immediate Invalidation**: Sessions can be killed globally in milliseconds if an account compromise or device posture change is detected.

## 3. Privacy-Preserving Identity
To prevent user tracking and correlation between services:
- **BBS+ Signatures**: Allow for zero-knowledge proofs of identity attributes.
- **Unlinkability**: Every presentation of a credential is cryptographically unique, ensuring Identity Providers and Relying Parties cannot collude to track user behavior.

## 4. Modern Hardened Defaults
- **PKCE Mandatory**: No OAuth flows without Proof Key for Code Exchange.
- **Exact Redirect Matching**: Preventing open redirector vulnerabilities.
- **Sender-Constrained Tokens**: Using DPoP to bind tokens to the client's cryptographic key.
