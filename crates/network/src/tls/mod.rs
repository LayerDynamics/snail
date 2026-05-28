//! TLS configuration and tokio-rustls stream helpers.

use std::io::BufReader;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::{NetworkError, Result};

/// Builders for rustls server/client configurations from PEM material.
pub struct TlsConfig;

impl TlsConfig {
    /// Build a server [`ServerConfig`] from a PEM cert chain + PEM private key.
    ///
    /// # Errors
    /// [`NetworkError::Tls`] if the PEM is malformed or contains no private key.
    pub fn server_from_pem(cert_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>> {
        let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| NetworkError::Tls(format!("reading certificates: {e}")))?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_bytes()))
            .map_err(|e| NetworkError::Tls(format!("reading private key: {e}")))?
            .ok_or_else(|| NetworkError::Tls("no private key found in PEM".into()))?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| NetworkError::Tls(format!("building server config: {e}")))?;
        Ok(Arc::new(config))
    }

    /// Build a client [`ClientConfig`] that trusts the given PEM root certificate(s).
    ///
    /// # Errors
    /// [`NetworkError::Tls`] if a root certificate cannot be parsed or added.
    pub fn client_trusting_pem(root_pem: &str) -> Result<Arc<ClientConfig>> {
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut BufReader::new(root_pem.as_bytes())) {
            let cert = cert.map_err(|e| NetworkError::Tls(format!("reading root cert: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| NetworkError::Tls(format!("adding root cert: {e}")))?;
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// Build a client [`ClientConfig`] that authenticates the peer against the
    /// **Mozilla PKIX trust anchors** (`webpki-roots`), with full WebPKI chain +
    /// hostname verification.
    ///
    /// This is the config to use whenever the peer's identity *must* be proven:
    /// fetching an MTA-STS policy over HTTPS (RFC 8461 §3.3 requires a valid
    /// PKIX certificate for `mta-sts.<domain>`), and relaying to a mail exchange
    /// under an MTA-STS `enforce` policy (RFC 8461 §4.1 — the certificate must
    /// chain to a trusted root and match the MX hostname). Unlike
    /// [`Self::opportunistic_client`], a certificate that does not validate
    /// causes the handshake to fail rather than be accepted.
    ///
    /// # Errors
    /// Infallible in practice; returns [`NetworkError::Tls`] only if the bundled
    /// trust anchor set is somehow unusable.
    pub fn pkix_client() -> Result<Arc<ClientConfig>> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if roots.is_empty() {
            return Err(NetworkError::Tls(
                "no PKIX trust anchors available from webpki-roots".into(),
            ));
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// Build a client [`ClientConfig`] for **opportunistic** outbound SMTP TLS.
    ///
    /// The returned config encrypts the connection but does **not** authenticate
    /// the peer's certificate — see [`OpportunisticServerVerifier`] for why that
    /// is the correct policy for MTA-to-MTA STARTTLS. The relay uses this to
    /// upgrade to TLS against any mail exchange that advertises `STARTTLS`.
    ///
    /// The active process-wide crypto provider is used when one has been
    /// installed (production); otherwise it falls back to the crate's default
    /// (`aws-lc-rs`), so the path also works in tests without an explicit install.
    /// The same provider backs both the config and the verifier's signature
    /// checks, keeping their supported schemes consistent.
    ///
    /// # Errors
    /// [`NetworkError::Tls`] if the provider cannot build a config for the
    /// default protocol versions.
    pub fn opportunistic_client() -> Result<Arc<ClientConfig>> {
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let verifier = Arc::new(OpportunisticServerVerifier {
            provider: Arc::clone(&provider),
        });
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| NetworkError::Tls(format!("building opportunistic client config: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// Build a client [`ClientConfig`] that authenticates the peer via **DANE**
    /// (RFC 7672) against the given DNSSEC-validated TLSA records, using
    /// [`crate::dane::DaneVerifier`]. The handshake succeeds only when the peer's
    /// certificate (chain) matches a usable TLSA association — there is no PKIX
    /// fallback. The relay uses this for an MX that publishes a secure TLSA RRset.
    ///
    /// The active process-wide crypto provider backs both the config and the
    /// verifier (falling back to `aws-lc-rs` when none is installed, so tests work
    /// without an explicit install).
    ///
    /// # Errors
    /// [`NetworkError::Tls`] if the provider cannot build a config for the default
    /// protocol versions.
    pub fn dane_client(tlsa: Vec<crate::dns::TlsaRecord>) -> Result<Arc<ClientConfig>> {
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let verifier = Arc::new(crate::dane::DaneVerifier::new(tlsa, Arc::clone(&provider)));
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| NetworkError::Tls(format!("building DANE client config: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }
}

/// A [`ServerCertVerifier`] for **opportunistic** SMTP TLS: it accepts any server
/// certificate (it does not authenticate the peer identity) yet still verifies
/// that the handshake signatures are valid under the presented key, using the
/// active crypto provider's algorithms.
///
/// This is the standard, correct policy for MTA-to-MTA STARTTLS in the absence of
/// DANE or MTA-STS. Arbitrary internet mail exchanges routinely present
/// certificates that chain to no shared trust anchor (self-signed, expired, or
/// with a hostname that does not match the MX), so there is nothing to
/// authenticate against. The realistic choice is between *encrypting against
/// passive eavesdroppers with an unauthenticated certificate* and *sending in
/// cleartext* — the former is strictly better. This verifier therefore trades
/// peer authentication for confidentiality, and never the reverse; authenticated
/// outbound TLS (DANE / MTA-STS) is deferred hardening that would layer on top.
#[derive(Debug)]
struct OpportunisticServerVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for OpportunisticServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // Opportunistic TLS authenticates nothing: accept any certificate so the
        // session is encrypted rather than falling back to cleartext.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Complete a server-side TLS handshake over `stream` using `config`.
///
/// # Errors
/// [`NetworkError::Io`] if the handshake fails.
pub async fn accept<IO>(config: Arc<ServerConfig>, stream: IO) -> Result<ServerTlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    TlsAcceptor::from(config)
        .accept(stream)
        .await
        .map_err(NetworkError::Io)
}

/// Initiate a client-side TLS handshake to `server_name` over `stream`.
///
/// # Errors
/// [`NetworkError::Tls`] if `server_name` is not a valid DNS name;
/// [`NetworkError::Io`] if the handshake fails.
pub async fn connect<IO>(
    config: Arc<ClientConfig>,
    server_name: &str,
    stream: IO,
) -> Result<ClientTlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| NetworkError::Tls(format!("invalid server name `{server_name}`: {e}")))?;
    TlsConnector::from(config)
        .connect(name, stream)
        .await
        .map_err(NetworkError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Generate a self-signed cert+key for `localhost` (PEM cert, PEM key).
    fn self_signed() -> (String, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (ck.cert.pem(), ck.key_pair.serialize_pem())
    }

    #[test]
    fn server_config_builds_from_pem() {
        let (cert, key) = self_signed();
        assert!(TlsConfig::server_from_pem(&cert, &key).is_ok());
    }

    #[test]
    fn server_config_rejects_pem_without_key() {
        let (cert, _key) = self_signed();
        assert!(TlsConfig::server_from_pem(&cert, "-----BEGIN X-----\n-----END X-----").is_err());
    }

    #[tokio::test]
    async fn loopback_tls_roundtrip() {
        let (cert_pem, key_pem) = self_signed();
        let server_config = TlsConfig::server_from_pem(&cert_pem, &key_pem).unwrap();
        let client_config = TlsConfig::client_trusting_pem(&cert_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = accept(server_config, tcp).await.unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect(client_config, "localhost", tcp).await.unwrap();
        tls.write_all(b"ping").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn opportunistic_client_handshakes_with_untrusted_cert() {
        // The server presents a self-signed cert the client has *never* seen.
        // A WebPKI client would reject it; the opportunistic client encrypts
        // anyway (it authenticates nothing, only the handshake signatures).
        let (cert_pem, key_pem) = self_signed();
        let server_config = TlsConfig::server_from_pem(&cert_pem, &key_pem).unwrap();
        let client_config = TlsConfig::opportunistic_client().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = accept(server_config, tcp).await.unwrap();
            let mut buf = [0u8; 6];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"secret");
            tls.write_all(b"ciphered").await.unwrap();
            tls.flush().await.unwrap();
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        // A server name that does not match the certificate's `localhost` SAN —
        // opportunistic verification ignores the name mismatch.
        let mut tls = connect(client_config, "mx.unknown.invalid", tcp)
            .await
            .unwrap();
        tls.write_all(b"secret").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 8];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ciphered");

        server.await.unwrap();
    }
}
