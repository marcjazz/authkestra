# The Authkestra Book

This book is the long-form companion to the API documentation: how Authkestra is put together, why
the boundaries fall where they do, and how to get a working integration running.

## How to read it, and how much to trust it

Per the [documentation hierarchy](../README.md#-documentation-hierarchy--source-of-truth), the book
is *best-effort end-user documentation, not the architectural source of truth*. The RFCs and the
code are ahead of it, and the project moves quickly. So chapters are labelled:

- Unlabelled prose describes code that exists today and was checked against the source.
- A section marked ***(shipped)*** exists and is usable now.
- A section marked ***(planned — not implemented)*** describes intent from
  [RFC-002](../rfc-002-next-gen-identity.md). **No code backs it.** Do not design against it, and do
  not treat it as a security property you have.

Chapters 5 (Authorization and Policies) and 7 (Admin API and AI Layer) are design documents in
their entirety; each carries a banner saying so.

When this book and the code disagree, the code wins. The most reliable references are:

- `cargo doc --workspace --no-deps --open` — the API as it actually is.
- `crates/authkestra/examples/` — every runnable example, each compiled by CI.
- [`docs/roadmap.md`](../roadmap.md) — what is actually being built next.

## Where to start

- New to the project? [Chapter 8: Getting Started Tutorial](ch08-getting-started-tutorial.md).
- Want the shape of the system? [Chapter 1](ch01-vision-and-architecture.md) for the vision,
  [Chapter 6](ch06-adapters-and-integrations.md) for what actually plugs into what.
- Writing an extension? [Chapter 3: Core Traits](ch03-core-traits.md) is transcribed from the
  current source.
