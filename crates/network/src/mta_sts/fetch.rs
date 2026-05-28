//! Hand-rolled HTTPS GET of an MTA-STS policy file (RFC 8461 §3.3).
//!
//! Deliberately minimal — no HTTP client dependency. The few rules that matter
//! for MTA-STS security are enforced explicitly: the peer is authenticated
//! against PKIX (the caller supplies a verifying client config) for the host
//! `mta-sts.<domain>`, HTTP redirects are **not** followed (a 3xx is an error),
//! a `Content-Length` is required (chunked/`Transfer-Encoding` responses are
//! refused), and both the response and the whole exchange are size- and
//! time-bounded so a hostile or hung policy host cannot stall the relay worker.

use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::dns::DnsResolver;
use crate::error::{NetworkError, Result};

/// Overall budget for a fetch: TCP connect + TLS handshake + request + response.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest policy body we will accept (real policies are a few hundred bytes).
const MAX_BODY: usize = 64 * 1024;
/// Largest header section we will buffer before the body.
const MAX_HEADERS: usize = 16 * 1024;

/// Fetch the MTA-STS policy body for `domain` over HTTPS, authenticating the
/// `mta-sts.<domain>` host against the PKIX roots in `tls`. `resolver` resolves
/// the policy host's address, so the final hop does not rely on the OS resolver.
///
/// # Errors
/// [`NetworkError`] if the host does not resolve, the connection/handshake fails,
/// the response is not a `200`, lacks a usable `Content-Length`, is chunked, or
/// the exchange exceeds [`FETCH_TIMEOUT`].
pub async fn fetch_policy(
    resolver: &dyn DnsResolver,
    tls: &Arc<ClientConfig>,
    domain: &str,
) -> Result<String> {
    let host = format!("mta-sts.{domain}");
    tokio::time::timeout(FETCH_TIMEOUT, fetch_inner(resolver, tls, &host))
        .await
        .map_err(|_| sts_err(&host, "policy fetch timed out"))?
}

async fn fetch_inner(
    resolver: &dyn DnsResolver,
    tls: &Arc<ClientConfig>,
    host: &str,
) -> Result<String> {
    let ip = resolver
        .lookup_ip(host)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| NetworkError::Resolve {
            name: host.to_string(),
            reason: "no address for MTA-STS policy host".into(),
        })?;

    let tcp = TcpStream::connect((ip.0, 443)).await?;
    let mut stream = crate::tls::connect(Arc::clone(tls), host, tcp).await?;

    // `Connection: close` lets the server end the stream so we read to EOF, but
    // the body length is still taken from Content-Length (chunked is rejected).
    let request = format!(
        "GET /.well-known/mta-sts.txt HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: snail-mta-sts\r\n\
         Accept: text/plain\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let cap = MAX_HEADERS + MAX_BODY;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > cap {
            return Err(sts_err(host, "response exceeds the size cap"));
        }
    }
    parse_http_response(&buf, host)
}

/// Parse a buffered HTTP/1.x response into the policy body. Enforces the
/// MTA-STS-relevant rules: status `200` only (no redirect-following), a present
/// and in-range `Content-Length`, and no `Transfer-Encoding`.
fn parse_http_response(raw: &[u8], host: &str) -> Result<String> {
    let sep =
        find_subslice(raw, b"\r\n\r\n").ok_or_else(|| sts_err(host, "no header/body separator"))?;
    let head = std::str::from_utf8(&raw[..sep]).map_err(|_| sts_err(host, "non-UTF-8 headers"))?;
    let body = &raw[sep + 4..];

    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| sts_err(host, "empty response"))?;
    let mut parts = status.split_whitespace();
    let proto = parts.next().unwrap_or("");
    if !proto.eq_ignore_ascii_case("HTTP/1.1") && !proto.eq_ignore_ascii_case("HTTP/1.0") {
        return Err(sts_err(host, &format!("unexpected protocol `{proto}`")));
    }
    let code: u16 = parts
        .next()
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| sts_err(host, "missing status code"))?;
    if code != 200 {
        // RFC 8461 §3.3: redirects MUST NOT be followed — any non-200 is a failure.
        return Err(sts_err(
            host,
            &format!("status {code} (redirects are not followed)"),
        ));
    }

    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if key.eq_ignore_ascii_case("transfer-encoding") {
            return Err(sts_err(host, "transfer-encoded responses are not accepted"));
        }
        if key.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .trim()
                    .parse()
                    .map_err(|_| sts_err(host, "invalid Content-Length"))?,
            );
        }
    }

    let len = content_length.ok_or_else(|| sts_err(host, "missing Content-Length"))?;
    if len > MAX_BODY {
        return Err(sts_err(host, "Content-Length exceeds the size cap"));
    }
    if body.len() < len {
        return Err(sts_err(host, "body shorter than Content-Length"));
    }
    std::str::from_utf8(&body[..len])
        .map(str::to_string)
        .map_err(|_| sts_err(host, "non-UTF-8 policy body"))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn sts_err(host: &str, reason: &str) -> NetworkError {
    NetworkError::Record {
        kind: "MTA-STS".into(),
        reason: format!("fetch from {host}: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(headers: &str, body: &str) -> Vec<u8> {
        format!("{headers}\r\n\r\n{body}").into_bytes()
    }

    #[test]
    fn parses_a_200_with_content_length() {
        let body = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 100\n";
        let raw = resp(
            &format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}",
                body.len()
            ),
            body,
        );
        assert_eq!(
            parse_http_response(&raw, "mta-sts.example.com").unwrap(),
            body
        );
    }

    #[test]
    fn accepts_http_1_0() {
        let body = "x";
        let raw = resp("HTTP/1.0 200 OK\r\nContent-Length: 1", body);
        assert_eq!(parse_http_response(&raw, "h").unwrap(), "x");
    }

    #[test]
    fn rejects_a_redirect() {
        let raw = resp(
            "HTTP/1.1 301 Moved\r\nLocation: https://evil/\r\nContent-Length: 0",
            "",
        );
        assert!(parse_http_response(&raw, "h").is_err());
    }

    #[test]
    fn rejects_chunked() {
        let raw = resp(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked",
            "5\r\nhello\r\n0\r\n",
        );
        assert!(parse_http_response(&raw, "h").is_err());
    }

    #[test]
    fn rejects_missing_content_length() {
        let raw = resp("HTTP/1.1 200 OK\r\nContent-Type: text/plain", "body");
        assert!(parse_http_response(&raw, "h").is_err());
    }

    #[test]
    fn rejects_oversized_content_length() {
        let raw = resp(
            &format!("HTTP/1.1 200 OK\r\nContent-Length: {}", MAX_BODY + 1),
            "",
        );
        assert!(parse_http_response(&raw, "h").is_err());
    }

    #[test]
    fn header_match_is_case_insensitive() {
        let body = "hi";
        let raw = resp("HTTP/1.1 200 OK\r\ncontent-length: 2", body);
        assert_eq!(parse_http_response(&raw, "h").unwrap(), "hi");
    }
}
