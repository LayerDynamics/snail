//! `snail-client` — a native demo CLI for the client binding.
//!
//! Reads a raw RFC 5322 message from stdin and prints the fields the WASM binding
//! exposes ([`ParsedMessage`]). It exercises the binding's logic natively (no
//! browser/JS runtime), which is handy for quick checks and as a smoke test.
//!
//! ```text
//! cargo run -p client < message.eml
//! ```

use std::io::{self, Read, Write};

use client::ParsedMessage;

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;

    match ParsedMessage::parse(&raw) {
        Ok(message) => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            writeln!(
                out,
                "subject:    {}",
                message.subject().unwrap_or_else(|| "(none)".into())
            )?;
            writeln!(
                out,
                "message-id: {}",
                message.message_id().unwrap_or_else(|| "(none)".into())
            )?;
            writeln!(out, "bytes:      {}", message.to_bytes().len())?;
            Ok(())
        }
        Err(err) => {
            eprintln!("parse error: {err}");
            std::process::exit(1);
        }
    }
}
