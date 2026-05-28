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
//! - `SNAIL_SPF_ENFORCE`       — reject (550) inbound mail on SPF `Fail` (default off: stamp `Received-SPF` only)
//! - `SNAIL_DMARC_ENFORCE`     — reject (550) inbound mail on a DMARC `reject` disposition (default off: stamp only)
//! - `SNAIL_GREYLIST`          — greylist the inbound port: defer (451) first contact for an unseen triplet (default off)
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

    // Resolve listener bind addresses up front: the inbound address decides
    // whether an ephemeral self-signed certificate is acceptable (see load_certs).
    let submission = env_or("SNAIL_SUBMISSION_ADDR", "127.0.0.1:587");
    let pop3 = env_or("SNAIL_POP3_ADDR", "127.0.0.1:110");
    let imap = env_or("SNAIL_IMAP_ADDR", "127.0.0.1:143");
    let inbound = env_or("SNAIL_INBOUND_ADDR", "127.0.0.1:2525");

    // STARTTLS material for the inbound receiver.
    let certs = load_certs(&domain, &inbound)?;

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

    // Inbound authentication: SPF + DKIM + DMARC are evaluated when a resolver is
    // available and stamped into Received-SPF / Authentication-Results. By default
    // they are advisory (stamp-only); SNAIL_SPF_ENFORCE rejects an SPF `Fail`, and
    // SNAIL_DMARC_ENFORCE rejects a DMARC `reject` disposition.
    let spf_enforce = env_flag("SNAIL_SPF_ENFORCE");
    let dmarc_enforce = env_flag("SNAIL_DMARC_ENFORCE");
    server = server
        .with_spf_enforcement(spf_enforce)
        .with_dmarc_enforcement(dmarc_enforce);
    tracing::info!(
        spf_enforce,
        dmarc_enforce,
        auth = server.resolver().is_some(),
        "inbound message authentication configured"
    );

    // Optional greylisting on the inbound port (off by default): defers the first
    // delivery for an unseen (network, sender, recipient) triplet.
    let greylist = env_flag("SNAIL_GREYLIST");
    if greylist {
        server = server.with_greylist(security::GreylistConfig::default());
        tracing::info!("inbound greylisting enabled");
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
        submission,
        pop3,
        imap,
        inbound,
        limits: ConcurrencyLimits::default(),
    };

    run(server, &listeners).await?;
    Ok(())
}

/// How to source the STARTTLS certificate, given whether one is configured and
/// where the inbound MX listener binds. Pure so the production guard is unit-tested.
#[derive(Debug, PartialEq, Eq)]
enum CertPlan {
    /// Use the operator-provided `SNAIL_TLS_CERT`/`SNAIL_TLS_KEY`.
    Configured,
    /// No cert configured, but the inbound port is non-production (dev): mint a
    /// fresh self-signed certificate (with a loud warning).
    EphemeralForDev,
    /// No cert configured on the production MX port (`:25`): refuse to start.
    RefuseProductionPort,
}

/// Decide the certificate plan. On the production MX port (`:25`) an ephemeral,
/// unverifiable, regenerated-every-boot self-signed cert makes inbound TLS
/// encryption-without-authentication, so a real certificate is mandatory there.
fn cert_plan(cert_configured: bool, inbound_addr: &str) -> CertPlan {
    if cert_configured {
        CertPlan::Configured
    } else if is_production_mx_port(inbound_addr) {
        CertPlan::RefuseProductionPort
    } else {
        CertPlan::EphemeralForDev
    }
}

/// Whether `addr` binds the standard SMTP MX port 25 (e.g. `0.0.0.0:25`,
/// `[::]:25`) — parsed from the trailing port so `:2525` does not match.
fn is_production_mx_port(addr: &str) -> bool {
    addr.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) == Some(25)
}

/// Load STARTTLS certificate material: the configured PEM cert+key if both
/// `SNAIL_TLS_CERT` and `SNAIL_TLS_KEY` are set; otherwise, a freshly generated
/// self-signed certificate for `domain` — **but only off the production MX port**.
/// On `:25` without a configured cert, this refuses to start rather than serve an
/// ephemeral, unverifiable certificate that changes on every restart.
fn load_certs(domain: &str, inbound_addr: &str) -> anyhow::Result<MailCerts> {
    let cert = std::env::var("SNAIL_TLS_CERT").ok();
    let key = std::env::var("SNAIL_TLS_KEY").ok();
    match cert_plan(cert.is_some() && key.is_some(), inbound_addr) {
        CertPlan::Configured => {
            let cert = std::fs::read_to_string(cert.expect("cert path present"))?;
            let key = std::fs::read_to_string(key.expect("key path present"))?;
            Ok(MailCerts::new(cert, key)?)
        }
        CertPlan::RefuseProductionPort => anyhow::bail!(
            "refusing to bind the production MX port ({inbound_addr}) without a TLS certificate: \
             set SNAIL_TLS_CERT and SNAIL_TLS_KEY to a real key pair. An ephemeral self-signed \
             certificate (regenerated every restart, unverifiable by peers) is not acceptable on :25 \
             — inbound TLS would be encryption without authentication."
        ),
        CertPlan::EphemeralForDev => {
            tracing::warn!(
                domain,
                inbound = inbound_addr,
                "SNAIL_TLS_CERT/SNAIL_TLS_KEY not set; generating an EPHEMERAL self-signed \
                 certificate. This is for development only — it is unverifiable and regenerated on \
                 every restart. Set SNAIL_TLS_CERT/SNAIL_TLS_KEY for any real deployment."
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

/// Read a boolean env flag: `1`, `true`, `yes`, or `on` (case-insensitive) are
/// true; anything else (including unset) is false.
fn env_flag(key: &str) -> bool {
    std::env::var(key).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_mx_port_is_detected_from_the_trailing_port() {
        assert!(is_production_mx_port("0.0.0.0:25"));
        assert!(is_production_mx_port("127.0.0.1:25"));
        assert!(is_production_mx_port("[::]:25"));
        // Dev/non-standard ports must NOT be treated as production.
        assert!(!is_production_mx_port("127.0.0.1:2525"));
        assert!(!is_production_mx_port("0.0.0.0:587"));
        assert!(!is_production_mx_port("127.0.0.1:255"));
        assert!(!is_production_mx_port("nonsense"));
    }

    #[test]
    fn cert_plan_refuses_ephemeral_cert_only_on_the_production_port() {
        // A configured cert is always honoured, regardless of port.
        assert_eq!(cert_plan(true, "0.0.0.0:25"), CertPlan::Configured);
        assert_eq!(cert_plan(true, "127.0.0.1:2525"), CertPlan::Configured);
        // No cert: refuse on :25, allow an ephemeral dev cert elsewhere.
        assert_eq!(
            cert_plan(false, "0.0.0.0:25"),
            CertPlan::RefuseProductionPort
        );
        assert_eq!(
            cert_plan(false, "127.0.0.1:2525"),
            CertPlan::EphemeralForDev
        );
    }

    #[test]
    fn load_certs_errors_on_production_port_without_a_cert() {
        // With SNAIL_TLS_CERT/KEY unset (the default test env), :25 must refuse.
        // (We avoid mutating process env — the absence of the vars is the case
        // under test, and cert_plan above proves the configured branch.)
        if std::env::var("SNAIL_TLS_CERT").is_err() && std::env::var("SNAIL_TLS_KEY").is_err() {
            assert!(load_certs("example.com", "0.0.0.0:25").is_err());
            // The dev port still succeeds (mints an ephemeral cert).
            assert!(load_certs("example.com", "127.0.0.1:2525").is_ok());
        }
    }
}
