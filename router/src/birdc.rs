//! A minimal client for BIRD's own control-socket protocol - talks directly to
//! `/run/bird.ctl`, not the `birdc` binary as a subprocess. BIRD's user guide documents this wire
//! format as stable ("the format of communication between BIRD and birdc is stable, see the
//! programmer's documentation"), and the actual framing (verified against a live BIRD 2.19.2 over
//! a raw `socat - UNIX-CONNECT:/run/bird.ctl` session, cross-checked against BIRD's own source in
//! `nest/cli.c`'s `cli_vprintf`) is simple enough that a full client library is more than this
//! daemon needs. Every reply line is `<4-digit code><sep><text>\n`, where `sep` is:
//! - `' '` (space): this is the **final** line of the response - reading stops here.
//! - `'-'` (dash): a continuation line with a *different* code than the previous one.
//! - no code at all (just a leading space before the text): a continuation line with the *same*
//!   code as the previous one (BIRD elides repeating it).
//!
//! Table-style responses (`show protocols`, `show ospf interface`) end with a trailing `0000 `
//! (empty message) sentinel line that `birdc`'s own interactive display filters out - easy to
//! miss by only ever looking at `birdc`'s human-facing output, as the doc comment on `command`'s
//! first draft did, before catching this against the raw socket.
//!
//! Reply codes are stable per BIRD's own convention (confirmed empirically: `0003`/`1002`/`2002`/
//! `1015`/`0000` for various successful replies, `8002` for a config syntax error) - codes `>=
//! 8000` mean an error, matching `nest/cli.h`'s own `8000`-based error code constants (e.g.
//! `CLI_ACCESS_DENIED_CODE = 8007`). See [`Reply::is_error`].
//!
//! On connect, BIRD immediately sends a one-line greeting (e.g. `0001 BIRD 2.19.2 ready.`, itself
//! a normal final-line-only reply) before any command is sent - `command` consumes and discards
//! it as part of every fresh connection.
//!
//! Ported from `slipmesh/operators`' `router/src/birdc.rs` (github.com/slipmesh/operators) -
//! verbatim, no changes: this module has zero coupling to Kubernetes or to how `router.yaml` is
//! shaped, it's a pure client for BIRD's own wire protocol.

use anyhow::{Context, Result, bail};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// A fully-parsed reply: the final line's numeric code, plus the concatenated text of every line
/// (code prefixes stripped, newlines kept) - equivalent to what `birdc <command>` would print,
/// minus `birdc`'s own filtering of the trailing `0000` sentinel line and minus its "BIRD ready."
/// banner passthrough.
pub struct Reply {
    pub code: u16,
    pub text: String,
}

impl Reply {
    /// BIRD's own convention (see this module's doc comment): a code `>= 8000` is an error.
    pub fn is_error(&self) -> bool {
        self.code >= 8000
    }
}

/// The 4-digit numeric code a line starts with, if it has one - present on every line except a
/// "continuation, same code as previous" one (a single leading space, no digits at all).
fn line_code(line: &str) -> Option<u16> {
    let bytes = line.as_bytes();
    if bytes.len() >= 5 && bytes[..4].iter().all(u8::is_ascii_digit) {
        line[..4].parse().ok()
    } else {
        None
    }
}

/// True if `line` (a single reply line, trailing newline included or not) is the final line of a
/// response - a real 4-digit code immediately followed by a space. A dash (continuation, code
/// changed) or no code at all (continuation, code unchanged) means more lines follow.
fn is_final_line(line: &str) -> bool {
    line.as_bytes().get(4) == Some(&b' ') && line_code(line).is_some()
}

/// Strips a leading `<4-digit code><sep>` if present, returning just the text - both the "code
/// changed" (`NNNN-`/`NNNN `) and "code unchanged" (single leading space) continuation forms are
/// exactly one byte in from this pattern's perspective (dash, space, or the text's own first
/// character), so a uniform "skip 4 digits + 1 separator byte if present" strip handles all three
/// shapes without needing to track the previous line's code at all. Only strips the 4-digit form
/// when byte 4 is actually a real separator (`' '`/`'-'`) - a malformed line with 4 leading digits
/// but no separator (e.g. a truncated `"0001\n"`) falls through untouched rather than having its
/// newline silently eaten as if it were one.
fn strip_code_prefix(line: &str) -> &str {
    if matches!(line.as_bytes().get(4), Some(b' ') | Some(b'-')) && line_code(line).is_some() {
        &line[5..]
    } else {
        line.strip_prefix(' ').unwrap_or(line)
    }
}

/// Sends `command` over a fresh connection to BIRD's control socket at `socket_path` and returns
/// the parsed [`Reply`].
pub async fn command(socket_path: &Path, command: &str) -> Result<Reply> {
    let stream = UnixStream::connect(socket_path).await.with_context(|| {
        format!(
            "failed to connect to {} for command {command:?}",
            socket_path.display()
        )
    })?;
    let mut reader = BufReader::new(stream);

    // Discard the connection greeting - always exactly one final line. Read as raw bytes (not
    // `read_line`'s `String` buffer, which errors outright on invalid UTF-8) and lossily decode,
    // matching the tolerance the old `birdc`-subprocess path had via `String::from_utf8_lossy`.
    let mut greeting_buf = Vec::new();
    let n = reader
        .read_until(b'\n', &mut greeting_buf)
        .await
        .context("failed to read BIRD's connection greeting")?;
    anyhow::ensure!(
        n != 0,
        "BIRD closed the connection immediately (no greeting) when connecting to {}",
        socket_path.display()
    );
    let greeting = String::from_utf8_lossy(&greeting_buf);
    if !is_final_line(&greeting) {
        bail!("unexpected BIRD greeting (not a single final line): {greeting:?}");
    }

    reader
        .get_mut()
        .write_all(format!("{command}\n").as_bytes())
        .await
        .with_context(|| format!("failed to send {command:?} to BIRD"))?;

    let mut text = String::new();
    let mut last_code = None;
    loop {
        let mut line_buf = Vec::new();
        let n = reader
            .read_until(b'\n', &mut line_buf)
            .await
            .with_context(|| format!("failed to read reply to {command:?}"))?;
        anyhow::ensure!(
            n != 0,
            "BIRD closed the connection mid-reply to {command:?}"
        );
        let line = String::from_utf8_lossy(&line_buf);
        if let Some(code) = line_code(&line) {
            last_code = Some(code);
        }
        let final_line = is_final_line(&line);
        text.push_str(strip_code_prefix(&line));
        if final_line {
            let code = last_code
                .with_context(|| format!("reply to {command:?} had no reply code at all"))?;
            return Ok(Reply { code, text });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_line_has_a_code_and_a_space() {
        assert!(is_final_line("0001 BIRD 2.19.2 ready.\n"));
        assert!(is_final_line("8002 syntax error\n"));
        assert!(is_final_line("0000 \n"));
    }

    #[test]
    fn dash_separated_line_is_a_continuation() {
        assert!(!is_final_line("0013-mesh       OSPF       master4    up\n"));
    }

    #[test]
    fn bare_leading_space_line_is_a_continuation() {
        assert!(!is_final_line("     Second line continues\n"));
    }

    #[test]
    fn parses_the_code_from_a_dash_or_space_separated_line() {
        assert_eq!(line_code("0013-mesh\n"), Some(13));
        assert_eq!(line_code("8002 syntax error\n"), Some(8002));
    }

    #[test]
    fn bare_leading_space_line_has_no_code() {
        assert_eq!(line_code("     kernel1 ...\n"), None);
    }

    #[test]
    fn strips_dash_prefix() {
        assert_eq!(strip_code_prefix("0013-mesh OSPF up\n"), "mesh OSPF up\n");
    }

    #[test]
    fn strips_final_line_prefix() {
        assert_eq!(strip_code_prefix("0001 ready.\n"), "ready.\n");
    }

    #[test]
    fn strips_bare_space_continuation_prefix() {
        assert_eq!(strip_code_prefix(" continued text\n"), "continued text\n");
    }

    #[test]
    fn leaves_a_line_with_no_prefix_at_all_untouched() {
        assert_eq!(strip_code_prefix("no prefix here\n"), "no prefix here\n");
    }

    #[test]
    fn leaves_a_line_with_digits_but_no_real_separator_untouched() {
        assert_eq!(strip_code_prefix("0001\n"), "0001\n");
    }

    #[test]
    fn codes_8000_and_above_are_errors() {
        assert!(
            Reply {
                code: 8002,
                text: String::new()
            }
            .is_error()
        );
        assert!(
            !Reply {
                code: 3,
                text: String::new()
            }
            .is_error()
        );
    }
}
