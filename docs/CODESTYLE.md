# Code style

## Formatting and lints

- `cargo fmt` with [`rustfmt.toml`](../rustfmt.toml): edition 2024, Unix newlines, field-init and
  `?` shorthand.
- `cargo clippy --all-targets --all-features -- -D warnings` with [`clippy.toml`](../clippy.toml);
  the shared CI workflow runs it with `-D warnings`, so a warning fails CI.
- `cargo deny --locked check licenses bans sources` against [`deny.toml`](../deny.toml): the binary
  is AGPL-3.0-only, so every dependency's licence has to be one that can ship under it.
- Markdown follows [`.markdownlint-cli2.jsonc`](../.markdownlint-cli2.jsonc).

## Layout

- One binary crate. Every module but `main.rs` opens with a `//!` comment saying its role.
- The logic that decides anything is in modules that take and return plain values: `config` (what
  the device should look like), `diff` (the plan per table), `sanitize`, `cli`, and
  `credentials::from_lookup`; `credentials::from_env` hands it the process environment.
- I/O stays in thin shims whose inputs and outputs are exactly what those modules take and give:
  `mikrotik` talks to the device, `patch` reads the file, `run` is the pipeline of one run and
  `converge` the order the tables are applied in.
- The mesh's config types and our other crates come from `sliplib`, by release tag; there is no
  local copy of their schema.

## Behaviour every change keeps

- The router's credentials come from the environment, never from a command-line flag, where a
  process listing would show them.
- The peer endpoint host, the one free-form string that reaches a RouterOS command attribute,
  passes the allow-list in `sanitize` first; names and lists rely on the config's own validation.
- A `--check` run does every read and every diff; only the writes are gated on it.

## Naming

- Types and functions say what they are for, not how.
- A new test is named for the behaviour it pins, as a sentence:
  `an_unset_port_defaults_to_the_api_ssl_port`. Older tests with short names keep them.
- `///` on a field of `Cli` is its `--help` text, so it says what the flag does.

## Error handling

- `anyhow::Result` throughout: this is a binary, and the error ends as one logged chain.
- The file is parsed and the credentials read before the device is connected to;
  `config::desired_state`'s checks run after the first read from the device and before any write.
  An error stops the run; tables already applied by then stay applied, since each table is written
  as it is reached.
- A new error names what it is about - the file, the variable, the node, the table row; errors
  from the device today carry no table or row. Most are built with `anyhow!`/`ensure!`, a source
  error added as text (`map_err(|e| anyhow!("…: {e}"))`); some add it as a cause with
  `.context(...)`.
- Three things are skipped without stopping the run: a value read back from the device that is
  missing or does not parse falls back to its default in a few places, `config` skips a `learn`
  range it cannot parse, and `mikrotik` skips a physically-connected address it cannot parse, the
  last two with a warning.
- `unwrap`/`expect` only in tests.

## Tests

- Tests sit in `#[cfg(test)]` modules at the end of the file they test: `mod tests` in most; in
  `diff.rs` one named module per table and three shared ones (`plan_tests`, `singleton_tests`,
  `passive_flag_tests`); `validate_endpoint_tests` in `sanitize.rs`.
  `tests/cli.rs` runs the binary as a caller does.
- A test pins behaviour of this repository's code, not another crate's or anything that holds by
  construction. A unit test pins what an error names, not its wording; `tests/cli.rs` pins the log
  lines a caller sees, wording included, since that output is the binary's interface - and with
  them the operating system's text for a missing file.
- WireGuard keys in fixtures come from `test_support`, addresses and names from the documentation
  ranges; nothing is taken from a live config.
- `cargo mutants` runs on changed code; what it may skip is listed with the reason in
  [`.cargo/mutants.toml`](../.cargo/mutants.toml). The device shims in `mikrotik` and `converge`
  have no unit tests yet.

## Comments

A new or changed comment says only why the code has to be that way - an external constraint or a
non-obvious consequence, including how RouterOS or the device's API behaves - and tells no history
of how the code got here and points at no file or function in another repository; the code says
what it does.
