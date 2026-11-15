# Code style

## Formatting and lints

- `cargo fmt` with [`rustfmt.toml`](../rustfmt.toml): edition 2024, Unix newlines, field-init and
  `?` shorthand.
- `cargo clippy --all-targets --all-features -- -D warnings` with [`clippy.toml`](../clippy.toml);
  a warning fails CI.
- `cargo deny --locked check licenses bans sources` against [`deny.toml`](../deny.toml): the binary
  is AGPL-3.0-only, so every dependency's licence has to be one that can ship under it.
- Markdown follows [`.markdownlint-cli2.jsonc`](../.markdownlint-cli2.jsonc).

## Layout

- One binary crate. The logic that decides anything is in pure modules - `config` (what the device
  should look like), `diff` (the plan per table), `credentials`, `sanitize`, `cli` - which take
  and return plain values.
- I/O stays in thin shims whose inputs and outputs are exactly what the pure modules take and give:
  `mikrotik` talks to the device, `patch` reads the file, `run` is the pipeline of one run and
  `converge` the order the tables are applied in.
- Types of the mesh's configs come from `sliplib`, never a local copy of their schema.

## Naming

- Types and functions say what they are for, not how.
- Tests are named for the behaviour they pin, as a sentence:
  `an_unset_port_defaults_to_the_api_ssl_port`.

## Error handling

- `anyhow::Result` throughout: this is a binary, and the error ends as one logged chain.
- Fail fast: a missing or malformed input, a missing variable or an invalid config aborts the run
  before the device is touched - never a silent fallback or a partial apply.
- An error names what it is about - the file, the variable, the node, the table row - and each
  layer adds the context it knows with `.context(...)`.
- `unwrap`/`expect` only in tests.

## Tests

- Tests sit in a `#[cfg(test)] mod tests` at the end of the file they test; `tests/cli.rs` runs the
  binary as a caller does.
- A test pins behaviour of this repository's code: not another crate's, not an error message's
  wording, nothing that holds by construction.
- Keys in fixtures come from `test_support`, addresses and names from the documentation ranges;
  nothing is taken from a live config.
- `cargo mutants` leaves no viable mutant missed; what it may skip is listed with the reason in
  [`.cargo/mutants.toml`](../.cargo/mutants.toml).

## Comments

Code says what it does; a comment says only why it has to be that way - an external constraint or
a non-obvious consequence, including how RouterOS or the device's API behaves. No history of how
the code got here, and no pointers to files or functions in other repositories.
