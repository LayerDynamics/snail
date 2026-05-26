//! `snail-server` — the Snail mail server entrypoint. Installs the TLS crypto
//! provider, initialises telemetry, composes the server from the environment,
//! provisions any configured users, binds the protocol listeners, and serves
//! until Ctrl-C.
//!
//! Environment:
//! - `SNAIL_DOMAIN`            — hosted domain (default `localhost`)
//! - `SNAIL_USERS`             — `user:pass,user2:pass2` to provision
//! - `SNAIL_SUBMISSION_ADDR`   — submission bind (default `127.0.0.1:587`)
//! - `SNAIL_POP3_ADDR`         — POP3 bind (default `127.0.0.1:110`)
//! - `SNAIL_IMAP_ADDR`         — IMAP bind (default `127.0.0.1:143`)
//!
//! `SNAIL_DATA_DIR` / `SNAIL_LOG` are read via `utilities::Config`.

use std::sync::Arc;

use snail_server::{Listeners, Server, ServerConfig, install_crypto_provider, run};
use telemetry::TelemetryConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_crypto_provider();
    let _telemetry = telemetry::init(&TelemetryConfig::stdout("snail-server"))?;

    let base = utilities::Config::from_env()?;
    let domain = std::env::var("SNAIL_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let config = ServerConfig {
        base,
        local_domains: vec![domain],
    };

    let mut server = Server::new(&config);
    if let Ok(users) = std::env::var("SNAIL_USERS") {
        for entry in users.split(',').filter(|e| !e.trim().is_empty()) {
            let (user, pass) = entry
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("SNAIL_USERS entry `{entry}` must be user:pass"))?;
            server.register_user(user.trim(), pass.trim())?;
        }
    }
    let server = Arc::new(server);

    let listeners = Listeners {
        submission: env_or("SNAIL_SUBMISSION_ADDR", "127.0.0.1:587"),
        pop3: env_or("SNAIL_POP3_ADDR", "127.0.0.1:110"),
        imap: env_or("SNAIL_IMAP_ADDR", "127.0.0.1:143"),
    };

    run(server, &listeners).await?;
    Ok(())
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
