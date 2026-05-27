//! `snail-server` — the Snail mail server entrypoint. Installs the TLS crypto
//! provider, initialises telemetry, composes the server from the environment
//! (STARTTLS certificate + durable relay spool + system DNS resolver), provisions
//! any configured users, binds the protocol listeners, and serves until Ctrl-C.
//!
//! Environment:
//! - `SNAIL_DOMAIN`            — hosted domain (default `localhost`)
//! - `SNAIL_USERS`             — `user:pass,user2:pass2` to provision
//! - `SNAIL_SUBMISSION_ADDR`   — submission bind (default `127.0.0.1:587`)
//! - `SNAIL_POP3_ADDR`         — POP3 bind (default `127.0.0.1:110`)
//! - `SNAIL_IMAP_ADDR`         — IMAP bind (default `127.0.0.1:143`)
//! - `SNAIL_INBOUND_ADDR`      — inbound MX bind (default `127.0.0.1:2525`; `:25` in prod needs privilege)
//! - `SNAIL_SPOOL_DIR`         — outbound relay queue (default `<data_dir>/spool`)
//! - `SNAIL_TLS_CERT`/`SNAIL_TLS_KEY` — PEM cert+key paths for STARTTLS (self-signed generated if unset)
//!
//! `SNAIL_DATA_DIR` / `SNAIL_LOG` are read via `utilities::Config`.

use std::sync::Arc;

use mail::MailCerts;
use network::HickoryResolver;
use snail_server::{
    ConcurrencyLimits, Listeners, OutboundSpool, Server, ServerConfig, install_crypto_provider, run,
};
use telemetry::TelemetryConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_crypto_provider();
    let _telemetry = telemetry::init(&TelemetryConfig::stdout("snail-server"))?;

    let base = utilities::Config::from_env()?;
    let domain = std::env::var("SNAIL_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let spool_dir = std::env::var("SNAIL_SPOOL_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| base.data_dir.join("spool"));
    let config = ServerConfig {
        base,
        local_domains: vec![domain.clone()],
    };

    // STARTTLS material for the inbound receiver.
    let certs = load_certs(&domain)?;

    // Durable outbound relay queue + system DNS resolver. If the resolver cannot
    // be built (no system config), the server still runs — inbound and local
    // delivery work; only outbound relay is disabled.
    let spool = Arc::new(OutboundSpool::open(&spool_dir)?);
    let mut server = Server::new(&config).with_tls(&certs)?;
    match HickoryResolver::from_system() {
        Ok(resolver) => {
            server = server.with_relay(Arc::new(resolver), Arc::clone(&spool));
            tracing::info!(spool = %spool_dir.display(), "outbound relay enabled");
        }
        Err(error) => {
            tracing::warn!(%error, "system DNS resolver unavailable; outbound relay disabled");
        }
    }

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
        inbound: env_or("SNAIL_INBOUND_ADDR", "127.0.0.1:2525"),
        limits: ConcurrencyLimits::default(),
    };

    run(server, &listeners).await?;
    Ok(())
}

/// Load STARTTLS certificate material: the configured PEM cert+key if both
/// `SNAIL_TLS_CERT` and `SNAIL_TLS_KEY` are set, otherwise a freshly generated
/// self-signed certificate for `domain`.
fn load_certs(domain: &str) -> anyhow::Result<MailCerts> {
    match (
        std::env::var("SNAIL_TLS_CERT"),
        std::env::var("SNAIL_TLS_KEY"),
    ) {
        (Ok(cert_path), Ok(key_path)) => {
            let cert = std::fs::read_to_string(&cert_path)?;
            let key = std::fs::read_to_string(&key_path)?;
            Ok(MailCerts::new(cert, key)?)
        }
        _ => {
            tracing::warn!(
                domain,
                "SNAIL_TLS_CERT/SNAIL_TLS_KEY not set; generating a self-signed certificate"
            );
            let generated = rcgen::generate_simple_self_signed(vec![domain.to_string()])?;
            Ok(MailCerts::new(
                generated.cert.pem(),
                generated.key_pair.serialize_pem(),
            )?)
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
