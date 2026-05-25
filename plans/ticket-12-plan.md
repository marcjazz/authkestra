# Plan for Issue #12: Central Orchestrator (AuthEngine)

## 1. Goal
Create `AuthEngine`, the central orchestrator that ties everything together, using the Typestate Builder Pattern.

## 2. Typestate Pattern Design

```rust
// Typestate markers
pub trait SessionStoreState {}
pub struct NoSessionStore;
impl SessionStoreState for NoSessionStore {}

pub struct WithSessionStore<S: SessionStore>(pub S);
impl<S: SessionStore> SessionStoreState for WithSessionStore<S> {}

// AuthEngine struct
pub struct AuthEngine<SessionState: SessionStoreState> {
    session_store: SessionState,
    // other fields like config, providers...
}

// AuthEngineBuilder struct
pub struct AuthEngineBuilder<SessionState: SessionStoreState> {
    session_store: SessionState,
}
```

## 3. Implementation Steps

1. Create `authkestra-engine/src/engine.rs` with `AuthEngine`, `AuthEngineBuilder`, and typestate definitions.
2. Implement `AuthEngine::builder()` returning an `AuthEngineBuilder<NoSessionStore>`.
3. Implement `.session_store(store)` on `AuthEngineBuilder<NoSessionStore>` which returns `AuthEngineBuilder<WithSessionStore<S>>`.
4. Implement `.build()` on `AuthEngineBuilder` to return `AuthEngine`.
5. Implement `create_session()` on `AuthEngine<WithSessionStore<S>>`.
6. Expose these types in `authkestra-engine/src/lib.rs`.
7. Update `authkestra-examples` to initialize `AuthEngine` using the new builder.
8. Add typestate tests in `authkestra-engine/src/tests.rs` or a new file to verify methods aren't available when the typestate is lacking.
9. Update `docs/` and `README.md` to reflect the new primary entry point.
