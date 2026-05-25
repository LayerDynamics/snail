//! TLS configuration and tokio-rustls stream helpers.

use std::io::BufReader;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
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
}
