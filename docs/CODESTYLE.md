# Code style

## Formatting and lints

- `cargo fmt` with [`rustfmt.toml`](../rustfmt.toml): edition 2024, Unix newlines, field-init and
  `?` shorthand.
- `cargo clippy --all-targets --all-features -- -D warnings` with [`clippy.toml`](../clippy.toml);
  a warning fails CI. Run it with the default features and `--no-default-features` too: the
  netlink half is a feature, and either build can warn where the other does not.
- `cargo deny --locked check licenses bans sources` with [`deny.toml`](../deny.toml).
- Markdown follows [`.markdownlint-cli2.jsonc`](../.markdownlint-cli2.jsonc).

## Layout

- One crate per daemon (`awg`, `router`, `nftables`) and one for the generator (`taloscfg`, binary
  `slipmesh-taloscfg`), each a library and its binary. `common` holds only what more than one
  of them uses.
- Netlink code sits behind a feature on by default, so `taloscfg`, which needs the config types
  alone, builds off Linux.
- Tests sit in a `#[cfg(test)] mod tests` at the end of the file they test; tests that run a
  binary sit in its crate's `tests/`.

## Naming

- Types and functions say what they are for, not how.
- Tests are named for the behaviour they pin, as a sentence:
  `a_config_renders_what_router_yaml_declares`.

## Error handling

- A refusal that a caller or a test tells apart is a `thiserror` enum of the crate's own; the rest
  is `anyhow`, with a context naming what failed.
- `unwrap`/`expect` only in tests.
- A type read from text has no `serde(flatten)`, `untagged` or internal `tag`: serde reads them
  through a buffer, and the refusal loses its key and line. Where one text holds several types'
  keys, each type is read from the text on its own, as `DaemonConfig::read` does. Writing through
  them loses nothing and stays allowed.
- A tool reads only the keys it uses. A value it only passes on passes as written: no type check,
  no refusal and no test for it.

## Tests

- A test pins behaviour of this repository's code: not another crate's, not an error message's
  wording, nothing that holds by construction.
- `cargo mutants` leaves no viable mutant missed; what it may skip is listed with the reason in
  [`.cargo/mutants.toml`](../.cargo/mutants.toml).

## Comments

Code says what it does; a comment says only why it has to be that way: an external constraint or
a non-obvious consequence, including how an external component behaves. No history of how the code
got here, and no pointers to files or functions in other repositories.
