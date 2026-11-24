# Code style

## Formatting and lints

The commands are in the README's [Development](../README.md#development) section.

- rustfmt with [`rustfmt.toml`](../rustfmt.toml): edition 2024, Unix newlines, field-init and `?`
  shorthand.
- clippy with [`clippy.toml`](../clippy.toml), warnings denied, over every build: all features, and
  the config-only one `taloscfg` uses.
- cargo-deny with [`deny.toml`](../deny.toml).
- markdownlint with [`.markdownlint-cli2.jsonc`](../.markdownlint-cli2.jsonc).

## Layout

- One crate per daemon (`awg`, `router`, `nftables`) and one for the generator (`taloscfg`, binary
  `slipmesh-taloscfg`), each a library and its binary. `common` holds the netlink helpers and
  what more than one crate uses.
- `common` has a `netlink` feature and `router` and `nftables` a `runtime` one, each on by default,
  and `[workspace.dependencies]` takes all three with `default-features = false`: `taloscfg`, which
  needs the config types and the template checks, builds off Linux. `awg` is netlink-only.
- Tests sit in a `#[cfg(test)] mod tests` at the end of the file they test; tests that run a
  binary sit in its crate's `tests/`.

## Naming

- Types and functions say what they are for, not how.
- Tests are named for the behaviour they pin, as a sentence:
  `a_config_renders_what_router_yaml_declares`.

## Error handling

- A refusal that a caller or a test tells apart is a `thiserror` enum of the crate's own; the rest
  is `anyhow`, with a context naming what failed, in a public signature too, since nothing here is
  published (`publish = false`).
- `unwrap`/`expect` only in tests.
- A type read from text has no `serde(flatten)`, `untagged` or internal `tag`: serde reads them
  through a buffer, and the refusal loses its key and line. Where one text holds several types'
  keys, each type is read from the text on its own, as `DaemonConfig::read` does. Writing through
  them loses nothing and stays allowed.
- A value put together in memory, such as merged patches, has no text, so each part is read from
  its own text before the parts are merged.
- `sliplib-yaml` refuses a YAML tag in what it reads, so no type takes one.
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
