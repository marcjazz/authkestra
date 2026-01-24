# Next Steps for authly-rs Development

This roadmap outlines the immediate next steps required to transition `authly` from its initial setup to a production-ready state, focusing on implementing core logic, persistence, and testing.

## 1. Implement Real Logic in `authly-providers-github`

The current implementation in [`authly-providers-github/src/lib.rs`](authly-providers-github/src/lib.rs:1) is likely mocked. Replace the mock implementation with actual OAuth flow logic to communicate with the GitHub API for user authentication.

*   **Action:** Update provider logic to handle the OAuth redirection, token exchange, and user information retrieval from GitHub.
*   **Dependencies:** Ensure you have the necessary secrets (Client ID and Secret) configured, likely through environment variables or a configuration layer not yet fully implemented.

## 2. Implement Real Persistence in `authly-session`

The session management layer in [`authly-session/src/lib.rs`](authly-session/src/lib.rs:1) must be upgraded from a likely in-memory store to a durable one.

*   **Action:** Integrate a production-ready persistence layer, such as **Redis** or a **SQL database** (e.g., PostgreSQL, SQLite via a suitable Rust ORM/client), to store session tokens and user context securely.
*   **Consideration:** Review the `authly-core` abstraction for session management to ensure compatibility with the chosen backend.

## 3. Run the Example with Real Credentials

Once the GitHub provider and session persistence are implemented, test the full flow using the provided example application.

*   **Action:** Set environment variables for `AUTHLY_GITHUB_CLIENT_ID` and `AUTHLY_GITHUB_CLIENT_SECRET` with valid credentials obtained from the GitHub Developer settings.
*   **Target:** Run the example application, likely found in [`examples/axum_github.rs`](examples/axum_github.rs:1).
*   **Verification:** Confirm that a user can successfully log in via GitHub and maintain a session across requests.

## 4. Add Comprehensive Tests

Ensure the reliability and correctness of the implemented features.

*   **Action:** Write unit and integration tests for:
    *   The concrete provider implementation in [`authly-providers-github`](authly-providers-github/src/lib.rs).
    *   The session management logic in [`authly-session`](authly-session/src/lib.rs).
    *   The overall authentication flow as implemented in the example application.
*   **Goal:** Achieve high test coverage for the core authentication and session handling logic.

---
**Status Update:** The `NEXT_STEPS.md` file has been created with the defined roadmap.