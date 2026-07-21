# Ticket: Implement OAuth 2.0 Device Authorization Grant (RFC 8628)

## Overview
Implement the **OAuth 2.0 Device Authorization Grant** (Device Flow, RFC 8628) in the `authkestra-op` crate. This grant type is designed for devices with limited or no browser capabilities (e.g., smart TVs, CLI tools).

## 1. Architectural Changes

### Data Layer (`authkestra-op/src/device.rs`)
Define a `DeviceCodeStore` trait to manage device codes and user codes (with TTLs and polling states).
```rust
pub enum DeviceCodeStatus {
    Pending,
    Approved(Identity),
    Denied,
}

pub struct DeviceCodeSession {
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: DateTime<Utc>,
    pub status: DeviceCodeStatus, 
}
```

**Security Invariant - Atomic Consumption (TOCTOU Prevention):** 
To prevent concurrent polling requests from generating multiple access tokens for the same device code, the trait MUST provide an atomic `consume_device_code` method. `get_device_code` followed by `delete_device_code` is explicitly forbidden for terminal states.

### Client Configuration (`authkestra-op/src/client.rs`)
- Add `GrantType::DeviceCode` to allow explicit opt-in per client.

## 2. API Endpoints

### Device Authorization Endpoint (`/device_authorization`)
Creates a new device authorization session.
- **Validates**: `client_id` and opt-in for `GrantType::DeviceCode`.
- **Generates**:
  - `device_code`: High-entropy string (UUID).
  - `user_code`: Short, user-friendly 8-character string (e.g., `WDJBMJHT`).
- **Stores**: The session in `DeviceCodeStore` with `Pending` status.
- **Returns**: `device_code`, `user_code`, `verification_uri`, `expires_in`, and polling `interval`.

### Token Endpoint (`/token`)
Add support for `grant_type=urn:ietf:params:oauth:grant-type:device_code`.
- **Validates**: `client_id` matches the session. Code is not expired.
- **State Handling**:
  - `Pending`: Return `authorization_pending` error.
  - `Denied`: Return `access_denied`.
  - `Approved(Identity)`: Atomically consume the session and issue tokens.

## 3. Definition of Done (DoD)
- [x] **Store Trait**: `DeviceCodeStore` defined with atomic `consume_device_code`.
- [x] **Endpoints**: `/device_authorization` and `/token` integration complete.
- [x] **Tracing**: Handlers adequately instrumented with `tracing` macros per `AGENTS.md`.
- [x] **Tests**: Automated integration tests verifying polling states, approval simulation, and token generation. All tests passing.
