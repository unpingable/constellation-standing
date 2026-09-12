# Standing: local first run

This journey exercises local mandate lifecycle and standing judgment. It does
not run AG, NQ, Nightshift, or a production identity service.

```sh
cargo test
cargo build -p standing-cli

ROOT="$(mktemp -d /tmp/constellation-standing-demo.XXXXXX)"
DB="$ROOT/standing.sqlite"
cargo run -p standing-cli -- --db "$DB" identity create \
  --name operator --location tutorial --secret tutorial-key > "$ROOT/operator.json"
cargo run -p standing-cli -- --db "$DB" genesis install \
  --identity "$ROOT/operator.json" --secret tutorial-key
cargo run -p standing-cli -- --db "$DB" genesis show
```

Every stateful command above names the isolated database explicitly. Do not
reuse the example secret outside this disposable fixture. A successful local
run proves only the exercised receipt and lifecycle boundaries. It does not
make the example identity suitable for another system.

Public source: <https://github.com/unpingable/constellation-standing>

Verification note: global `--db`, `identity create`, `genesis install`, and
`genesis show` were checked against `crates/standing-cli/src/main.rs`. The
prescribed component test is `cargo test`. On 2026-09-12, the source tree
completed `cargo test --offline --locked -j1` and
`cargo build --offline --locked -j1 -p standing-cli`, then completed this
isolated identity, genesis-install, and genesis-show fixture successfully.
These are local source and SQLite lifecycle checks, not a production mandate,
identity-service, or deployment qualification.
