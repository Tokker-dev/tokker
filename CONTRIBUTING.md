# Contributing

## Bounties and outside pull requests

There are no bounties on this project. Issues here are the team's planning notes, not paid tasks.
Pull requests from people outside the team are only reviewed when the change was discussed in the
issue first and a maintainer agreed to it. Other pull requests are closed without review.

The checks below are what CI runs (`/.github/workflows/ci.yml`). Work that
fails them is not done. Commits follow [Conventional Commits][cc] and name the
issue number.

## Rust

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo build -p tokker-worker --target wasm32-unknown-unknown
```

The duplicate check — no `cratefield-*` crate may appear from two sources:

```sh
tree=$(mktemp)
if ! cargo tree -d --depth 0 > "$tree"; then
  echo "ERROR: cargo tree failed; duplicate check could not run"
  exit 1
fi
cat "$tree"
if grep cratefield "$tree"; then
  echo "ERROR: duplicate cratefield crate detected"
  exit 1
fi
```

## Data (Node 22)

```sh
bun install --frozen-lockfile
bun run validate
bun run test
```

[cc]: https://www.conventionalcommits.org/
