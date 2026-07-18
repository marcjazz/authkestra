# Structural Cleanup: Documentation & Agent Rules

## Goal
Unify agent rules and organize loose documentation files to prevent drift and clarify the source of truth.

## Steps
1. **Agent Rules Drift**
   - Delete the four divergent copies of `AGENTS.md` in `.roo/rules-*/` or replace them with one-line pointers/symlinks to the root `AGENTS.md`.
   - Add a lint or CI check (if symlinks aren't used) to ensure they remain in sync.

2. **Research & Loose Files**
   - Move `deep-search.md` from the repo root to `docs/research/deep-search.md`.
   - Prepend a one-line header explaining that it is reference material, not authored documentation.
   - Fill in the blank `git clone` template in `CONTRIBUTING.md`.

3. **Docs Hierarchy**
   - Create `docs/README.md` to define the documentation hierarchy: "RFCs are the design record, `roadmap.md` is what's actually being built next, `book/` is user-facing docs and may lag behind."

4. **Gitignore Cleanup**
   - Remove redundant `.gitignore` files from `authkestra-session/` and `authkestra-axum/` which only contain `/target` (already covered by root `.gitignore`).
