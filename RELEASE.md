# Releasing

## This repository is a fork

`stephane-segning/authkestra` is a **fork of [`marcjazz/authkestra`](https://github.com/marcjazz/authkestra)**.

That matters more than it usually would, because **`marcjazz` is the sole crates.io owner** of the
published `authkestra*` crates. This fork does not publish them and cannot: it has no ownership of
those names on the registry.

Verify either fact yourself:

```sh
gh api repos/stephane-segning/authkestra --jq '{fork: .fork, parent: .parent.full_name}'
curl -s https://crates.io/api/v1/crates/authkestra-op/owner_user | jq '.users[].login'
```

## Where the source of a published version lives

Upstream carries a per-crate tag for every published version — `authkestra-op-v0.3.4` and so on.
To audit what a given version actually contains:

```sh
# what exists on the registry, with publish timestamps and yank status
curl -s https://index.crates.io/au/th/authkestra-op | jq -c '{vers, yanked}'

# the matching tag upstream
git ls-remote --tags https://github.com/marcjazz/authkestra | grep 'authkestra-op-v0.3.4'
```

**Known gap — this fork's own tags lag upstream.** Its highest tag is `0.2.1` and its `Cargo.toml`
sits at an unreleased `0.2.4`. Anyone auditing a `=0.3.x` pin must look at `marcjazz/authkestra`,
not here. No tags have been created in this fork for 0.3.x versions, deliberately: those commits are
not reachable from this fork's history, so a tag placed here would point at something that is not
what was published. **A tag that looks authoritative and is wrong is worse than a missing one.**

## Downstream consumers

`vpay` pins `authkestra-op = "=0.3.4"`; `vsms` pins `=0.3.3`. Both therefore depend, at exact
versions, on crates owned by a third party. **Nobody on this side can patch, yank, or ship a fix for
them independently.** Before authkestra becomes load-bearing for more services, resolve that one of
three ways:

1. obtain crates.io co-ownership from `marcjazz`;
2. formalise the upstream relationship and contribute there rather than maintaining a divergent
   fork; or
3. fork-and-rename under an org you control, and own the names outright.

This is a relationship decision, not only a technical one — but it should be a deliberate one.

## Cutting a release (whoever holds publish rights)

`.github/workflows/publish.yml` publishes the workspace in dependency order:
foundation → core → advanced → frameworks → root, chained with `needs:`.

**Every publish requires a tag on `HEAD`.** The `verify-tag` job gates the whole chain and fails the
run when `git describe --exact-match --tags HEAD` finds nothing. Of the workflow's three triggers,
only `push: tags: v*` guarantees this; `workflow_dispatch` and `release: created` can otherwise run
against an arbitrary untagged commit, which is exactly how a version becomes untraceable.

So:

1. Bump versions and merge.
2. Tag the release commit and push the tag — that alone triggers the workflow.
3. If you instead dispatch manually, make sure the ref you dispatch against is tagged, or the run
   fails at the gate before touching the registry.

### After releasing, verify

```sh
git ls-remote --tags origin | grep "$VERSION"
curl -s https://index.crates.io/au/th/authkestra-op | jq -c 'select(.vers=="'"$VERSION"'")'
```

Both should return a row. If the registry has a version the tag list does not, that is the defect
this document exists to prevent — fix it before cutting the next release.
