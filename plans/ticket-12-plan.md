# Plan for Issue #12: Central Orchestrator (Engine)

## 1. Goal
Create `Engine`, the central orchestrator that ties everything together, using the Typestate Builder Pattern.

## 2. Typestate Pattern Design

```rust
// Typestate markers
pub trait SessionStoreState {}
pub struct NoSessionStore;
impl SessionStoreState for NoSessionStore {}

pub struct WithSessionStore<S: SessionStore>(pub S);
impl<S: SessionStore> SessionStoreState for WithSessionStore<S> {}

// Engine struct
pub struct Engine<SessionState: SessionStoreState> {
    session_store: SessionState,
    // other fields like config, providers...
}

// EngineBuilder struct
pub struct EngineBuilder<SessionState: SessionStoreState> {
    session_store: SessionState,
}
```

## 3. Implementation Steps

1. Create `authkestra-engine/src/engine.rs` with `Engine`, `EngineBuilder`, and typestate definitions.
2. Implement `Engine::builder()` returning an `EngineBuilder<NoSessionStore>`.
3. Implement `.session_store(store)` on `EngineBuilder<NoSessionStore>` which returns `EngineBuilder<WithSessionStore<S>>`.
4. Implement `.build()` on `EngineBuilder` to return `Engine`.
5. Implement `create_session()` on `Engine<WithSessionStore<S>>`.
6. Expose these types in `authkestra-engine/src/lib.rs`.
7. Update `authkestra-examples` to initialize `Engine` using the new builder.
8. Add typestate tests in `authkestra-engine/src/tests.rs` or a new file to verify methods aren't available when the typestate is lacking.
9. Update `docs/` and `README.md` to reflect the new primary entry point.
