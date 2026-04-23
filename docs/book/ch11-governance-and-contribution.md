# Chapter 11: Governance & Contribution

Authkestra is an open-source project driven by its community. This chapter outlines how the project is governed, how decisions are made, and how you can contribute.

## Project Governance

Authkestra operates under a benevolent dictator for now (BDFL) model, supported by core maintainers.

- **Core Maintainers**: Responsible for reviewing PRs, managing releases, and guiding the overall architecture.
- **Contributors**: Anyone who submits code, documentation, or issues.

We are committed to fostering an inclusive, welcoming community. All participants must adhere to our [Code of Conduct](../community.md).

## The RFC Process

For significant architectural changes, new features, or major API modifications, we require an RFC (Request for Comments). The RFC process ensures that major changes are well-thought-out, discussed, and documented before implementation begins.

1. **Draft an RFC**: Copy the RFC template and describe the motivation, design, and drawbacks of your proposal.
2. **Submit a PR**: Open a Pull Request adding your draft to the `docs/rfcs` directory.
3. **Discussion**: The community and maintainers will discuss the proposal, ask questions, and suggest refinements.
4. **Acceptance**: Once consensus is reached, the RFC is merged and marked as "Accepted." Implementation can then begin.

_(See `docs/rfc-001-architecture-migration.md` for an example of a past RFC)._

## Contributing Code

We welcome contributions of all sizes, from typo fixes to new providers.

### Code Style and Standards

- **Formatting**: All code must be formatted using `rustfmt`. Run `cargo fmt` before submitting.
- **Linting**: Code must pass `clippy` without warnings. Run `cargo clippy -- -D warnings`.
- **Testing**: New features must include relevant tests. Bug fixes should include a regression test.
- **Documentation**: Public APIs must be documented using rustdoc comments (`///`).

### Pull Request Workflow

1. **Fork the Repository**: Create a fork and branch off `main`.
2. **Make Changes**: Implement your feature or fix.
3. **Commit Messages**: Write clear, descriptive commit messages.
4. **Open a PR**: Submit your PR. Ensure CI passes.
5. **Review**: Address any feedback from maintainers. Once approved, your PR will be merged!

## Release Cycles

Authkestra follows Semantic Versioning (SemVer).

- **Major Releases (X.0.0)**: Contain breaking API changes. These are infrequent and planned well in advance via RFCs.
- **Minor Releases (0.X.0)**: Introduce new features in a backward-compatible manner. We aim for minor releases every 4-6 weeks.
- **Patch Releases (0.0.X)**: Address bugs, security vulnerabilities, or minor documentation updates. Released as needed.

Before a 1.0 release, we reserve the right to make breaking changes in minor versions (0.X), though we strive to minimize this and provide clear migration paths.

Thank you for being part of the Authkestra community!
