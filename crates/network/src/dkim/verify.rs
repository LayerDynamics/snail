//! DKIM verification orchestration (RFC 6376 §6, RFC 8463): for each
//! `DKIM-Signature` in a message, fetch the public key via DNS, check the body
//! hash, build the signed-header hash, and verify the signature.
//!
//! Operates on the verbatim message bytes (preserved end-to-end by the mail
//! engine), so canonicalization sees exactly what the signer signed.
//!
//! DNS-error note: as with SPF, the resolver collapses "no key" and transient
//! failures, so a failed key lookup is reported as `PermError` ("no key");
//! distinguishing `TempError` is a future resolver enhancement.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use rsa::Pkcs1v15Sign;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

use crate::dkim::canonicalize::{canonicalize_body, canonicalize_header};
use crate::dkim::signature::{Algorithm, DkimSignature};
use crate::dns::DnsResolver;

/// The result of verifying one DKIM signature (RFC 6376 §3.9, aligned with the
/// values used in an `Authentication-Results` header and by DMARC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimResult {
    /// The signature verified.
    Pass,
    /// The signature did not verify (bad signature, body hash mismatch, revoked
    /// key, or expired).
    Fail,
    /// The `DKIM-Signature` or key is malformed / unsupported / not found.
    PermError,
    /// A transient error prevented verification (reserved; see module note).
    TempError,
}

impl DkimResult {
    /// The lowercase token for an `Authentication-Results` `dkim=` field.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DkimResult::Pass => "pass",
            DkimResult::Fail => "fail",
            DkimResult::PermError => "permerror",
            DkimResult::TempError => "temperror",
        }
    }
}

/// The outcome of verifying one `DKIM-Signature`: its signing domain (`d=`),
/// selector (`s=`), and result. DMARC aligns the `From:` domain against `domain`
/// of any `Pass` outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimOutcome {
    /// The `d=` signing domain (empty if the signature was unparseable).
    pub domain: String,
    /// The `s=` selector (empty if unparseable).
    pub selector: String,
    /// The verification result.
    pub result: DkimResult,
}

/// Verify every `DKIM-Signature` in `raw_message`. Returns one [`DkimOutcome`]
/// per signature, in header order; an empty `Vec` means the message carries no
/// DKIM signature (DMARC treats that as `dkim=none`).
pub async fn verify(resolver: &dyn DnsResolver, raw_message: &[u8]) -> Vec<DkimOutcome> {
    let (header_section, body) = split_message(raw_message);
    let fields = parse_fields(header_section);
    let mut outcomes = Vec::new();
    for (idx, field) in fields.iter().enumerate() {
        if !field.name.eq_ignore_ascii_case("DKIM-Signature") {
            continue;
        }
        match DkimSignature::parse(&field.value) {
            Ok(sig) => {
                let result = verify_one(resolver, &fields, idx, &sig, body).await;
                outcomes.push(DkimOutcome {
                    domain: sig.domain.clone(),
                    selector: sig.selector.clone(),
                    result,
                });
            }
            Err(_) => outcomes.push(DkimOutcome {
                domain: String::new(),
                selector: String::new(),
                result: DkimResult::PermError,
            }),
        }
    }
    outcomes
}

/// Verify a single parsed signature against the message.
async fn verify_one(
    resolver: &dyn DnsResolver,
    fields: &[HeaderField],
    sig_idx: usize,
    sig: &DkimSignature,
    body: &[u8],
) -> DkimResult {
    // 1. Expiration (x=).
    if let Some(exp) = sig.expiration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now > exp {
            return DkimResult::Fail;
        }
    }

    // 2. Body hash (bh=): canonicalize, apply the l= octet limit, SHA-256.
    let canon_body = canonicalize_body(body, sig.body_canon);
    let hashed = match sig.body_length {
        Some(l) => &canon_body[..l.min(canon_body.len())],
        None => &canon_body[..],
    };
    if Sha256::digest(hashed).as_slice() != sig.body_hash.as_slice() {
        return DkimResult::Fail;
    }

    // 3. Public key (DNS).
    let record = match resolver.lookup_dkim(&sig.selector, &sig.domain).await {
        Ok(record) => record,
        Err(_) => return DkimResult::PermError, // key not found / transient
    };
    if record.public_key.is_empty() {
        return DkimResult::Fail; // empty p= → revoked key (RFC 6376 §3.6.1)
    }
    // The `k=` key type must match the `a=` algorithm family.
    if let Some(k) = &record.key_type {
        let matches = match sig.algorithm {
            Algorithm::RsaSha256 => k.eq_ignore_ascii_case("rsa"),
            Algorithm::Ed25519Sha256 => k.eq_ignore_ascii_case("ed25519"),
        };
        if !matches {
            return DkimResult::PermError;
        }
    }
    let key_der = match BASE64.decode(record.public_key.as_bytes()) {
        Ok(der) => der,
        Err(_) => return DkimResult::PermError,
    };

    // 4. Header hash over the signed headers + this DKIM-Signature (b= emptied).
    let header_hash = compute_header_hash(fields, sig_idx, sig);

    // 5. Verify the signature.
    match sig.algorithm {
        Algorithm::RsaSha256 => {
            let Some(public) = rsa_public_key(&key_der) else {
                return DkimResult::PermError;
            };
            match public.verify(Pkcs1v15Sign::new::<Sha256>(), &header_hash, &sig.signature) {
                Ok(()) => DkimResult::Pass,
                Err(_) => DkimResult::Fail,
            }
        }
        Algorithm::Ed25519Sha256 => {
            let key_bytes: [u8; 32] = match key_der.as_slice().try_into() {
                Ok(b) => b,
                Err(_) => return DkimResult::PermError,
            };
            let Ok(verifying) = VerifyingKey::from_bytes(&key_bytes) else {
                return DkimResult::PermError;
            };
            let sig_bytes: [u8; 64] = match sig.signature.as_slice().try_into() {
                Ok(b) => b,
                Err(_) => return DkimResult::PermError,
            };
            let ed_sig = EdSignature::from_bytes(&sig_bytes);
            // RFC 8463: Ed25519 (PureEdDSA) over the SHA-256 digest of the header.
            match verifying.verify_strict(&header_hash, &ed_sig) {
                Ok(()) => DkimResult::Pass,
                Err(_) => DkimResult::Fail,
            }
        }
    }
}

/// Build the SHA-256 of the signed-header set: each `h=` field (consumed
/// bottom-up, excluding the signature being verified), then this DKIM-Signature
/// with its `b=` value emptied and **no** trailing CRLF (RFC 6376 §3.7).
fn compute_header_hash(fields: &[HeaderField], sig_idx: usize, sig: &DkimSignature) -> Vec<u8> {
    let mut input = Vec::new();
    let mut consumed: HashSet<usize> = HashSet::new();
    for name in &sig.signed_headers {
        // Pick the highest-indexed unconsumed field of this name, skipping the
        // signature field itself (it is appended last).
        let pick = fields.iter().enumerate().rev().find(|(i, f)| {
            *i != sig_idx && !consumed.contains(i) && f.name.eq_ignore_ascii_case(name)
        });
        if let Some((i, field)) = pick {
            consumed.insert(i);
            input.extend_from_slice(&canonicalize_header(
                &field.name,
                &field.value,
                sig.header_canon,
                true,
            ));
        }
        // An h= entry with no matching field contributes the null string (skip).
    }
    let current = &fields[sig_idx];
    input.extend_from_slice(&canonicalize_header(
        &current.name,
        &sig.b_stripped_value,
        sig.header_canon,
        false,
    ));
    Sha256::digest(&input).to_vec()
}

/// Import an RSA public key from DER: SubjectPublicKeyInfo (the usual DKIM `p=`
/// encoding) or a bare PKCS#1 `RSAPublicKey`.
fn rsa_public_key(der: &[u8]) -> Option<RsaPublicKey> {
    RsaPublicKey::from_public_key_der(der)
        .ok()
        .or_else(|| RsaPublicKey::from_pkcs1_der(der).ok())
}

/// One parsed header field: the raw name and the raw value (everything after the
/// first `:`, up to but not including the field's terminating CRLF, with internal
/// folding CRLFs preserved).
struct HeaderField {
    name: String,
    value: Vec<u8>,
}

/// Split a raw message into its header section and body on the first blank line.
fn split_message(raw: &[u8]) -> (&[u8], &[u8]) {
    match find_subslice(raw, b"\r\n\r\n") {
        Some(p) => (&raw[..p], &raw[p + 4..]),
        None => (raw, &[]),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse the header section into ordered fields, joining folded continuation
/// lines (those beginning with WSP) into the preceding field.
fn parse_fields(headers: &[u8]) -> Vec<HeaderField> {
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut started = false;
    for line in split_crlf_lines(headers) {
        let is_continuation = matches!(line.first(), Some(b' ' | b'\t'));
        if is_continuation && started {
            current.extend_from_slice(b"\r\n");
            current.extend_from_slice(line);
        } else {
            if started {
                blocks.push(std::mem::take(&mut current));
            }
            current = line.to_vec();
            started = true;
        }
    }
    if started {
        blocks.push(current);
    }
    blocks
        .into_iter()
        .filter_map(|block| {
            let colon = block.iter().position(|&b| b == b':')?;
            let name = String::from_utf8_lossy(&block[..colon]).trim().to_string();
            Some(HeaderField {
                name,
                value: block[colon + 1..].to_vec(),
            })
        })
        .collect()
}

/// Split bytes on CRLF, returning each line without its terminator.
fn split_crlf_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let (mut start, mut i) = (0usize, 0usize);
    while i + 1 < bytes.len() {
        if bytes[i] == b'\r' && bytes[i + 1] == b'\n' {
            lines.push(&bytes[start..i]);
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    lines.push(&bytes[start..]);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{AddressRecord, MxRecord, PtrRecord, TxtRecord};
    use crate::error::Result;
    use async_trait::async_trait;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::{Signer, SigningKey};
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    use crate::dkim::canonicalize::{BodyCanon, HeaderCanon, parse_canon};

    /// A resolver that returns canned `<selector>._domainkey.<domain>` TXT records.
    struct KeyResolver {
        txt: BTreeMap<String, String>,
    }

    #[async_trait]
    impl DnsResolver for KeyResolver {
        async fn lookup_mx(&self, _d: &str) -> Result<Vec<MxRecord>> {
            Ok(vec![])
        }
        async fn lookup_ip(&self, _h: &str) -> Result<Vec<AddressRecord>> {
            Ok(vec![])
        }
        async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>> {
            Ok(self
                .txt
                .get(name)
                .map(|v| vec![TxtRecord(v.clone())])
                .unwrap_or_default())
        }
        async fn reverse_lookup(&self, _ip: IpAddr) -> Result<Vec<PtrRecord>> {
            Ok(vec![])
        }
    }

    /// Build the header-hash input the same way the verifier does, for a chosen
    /// set of already-canonical-aware header fields (name, raw value).
    fn header_hash_input(
        signed: &[(&str, &[u8])],
        dkim_sig_value_b_empty: &[u8],
        canon: HeaderCanon,
    ) -> Vec<u8> {
        let mut input = Vec::new();
        for (name, value) in signed {
            input.extend_from_slice(&canonicalize_header(name, value, canon, true));
        }
        input.extend_from_slice(&canonicalize_header(
            "DKIM-Signature",
            dkim_sig_value_b_empty,
            canon,
            false,
        ));
        input
    }

    /// Sign `body` + the `From`/`Subject` headers, returning a full signed message
    /// and the public-key TXT record value to publish.
    struct Signed {
        message: Vec<u8>,
        selector: String,
        domain: String,
        txt: String,
    }

    fn build_message(from: &[u8], subject: &[u8], body: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"From:");
        m.extend_from_slice(from);
        m.extend_from_slice(b"\r\nSubject:");
        m.extend_from_slice(subject);
        m.extend_from_slice(b"\r\n\r\n");
        m.extend_from_slice(body);
        m
    }

    fn sign_rsa(from: &[u8], subject: &[u8], body: &[u8], key: &RsaPrivateKey) -> Signed {
        let (hc, bc) = (HeaderCanon::Relaxed, BodyCanon::Relaxed);
        assert_eq!(parse_canon(Some("relaxed/relaxed")), (hc, bc));
        let bh = B64.encode(Sha256::digest(canonicalize_body(body, bc)));
        let value_b_empty = format!(
            " v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel;\r\n h=from:subject; bh={bh}; b="
        );
        let input = header_hash_input(
            &[("From", from), ("Subject", subject)],
            value_b_empty.as_bytes(),
            hc,
        );
        let header_hash = Sha256::digest(&input);
        let sig = key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &header_hash)
            .unwrap();
        let b = B64.encode(sig);
        let der = key.to_public_key().to_public_key_der().unwrap();
        let txt = format!("v=DKIM1; k=rsa; p={}", B64.encode(der.as_bytes()));

        let mut message = Vec::new();
        message.extend_from_slice(b"DKIM-Signature:");
        message.extend_from_slice(value_b_empty.as_bytes());
        message.extend_from_slice(b.as_bytes());
        message.extend_from_slice(b"\r\n");
        message.extend_from_slice(&build_message(from, subject, body));
        Signed {
            message,
            selector: "sel".into(),
            domain: "example.com".into(),
            txt,
        }
    }

    fn sign_ed25519(from: &[u8], subject: &[u8], body: &[u8], key: &SigningKey) -> Signed {
        let (hc, bc) = (HeaderCanon::Relaxed, BodyCanon::Relaxed);
        let bh = B64.encode(Sha256::digest(canonicalize_body(body, bc)));
        let value_b_empty = format!(
            " v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=ed;\r\n h=from:subject; bh={bh}; b="
        );
        let input = header_hash_input(
            &[("From", from), ("Subject", subject)],
            value_b_empty.as_bytes(),
            hc,
        );
        let header_hash = Sha256::digest(&input);
        let sig = key.sign(&header_hash);
        let b = B64.encode(sig.to_bytes());
        let txt = format!(
            "v=DKIM1; k=ed25519; p={}",
            B64.encode(key.verifying_key().to_bytes())
        );

        let mut message = Vec::new();
        message.extend_from_slice(b"DKIM-Signature:");
        message.extend_from_slice(value_b_empty.as_bytes());
        message.extend_from_slice(b.as_bytes());
        message.extend_from_slice(b"\r\n");
        message.extend_from_slice(&build_message(from, subject, body));
        Signed {
            message,
            selector: "ed".into(),
            domain: "example.com".into(),
            txt,
        }
    }

    fn resolver_for(s: &Signed) -> KeyResolver {
        let mut txt = BTreeMap::new();
        txt.insert(
            format!("{}._domainkey.{}", s.selector, s.domain),
            s.txt.clone(),
        );
        KeyResolver { txt }
    }

    #[tokio::test]
    async fn rsa_sha256_round_trip_passes() {
        let key = RsaPrivateKey::new(&mut rand_core::OsRng, 1024).unwrap();
        let s = sign_rsa(b" Alice <a@example.com>", b" Hello", b"Hi Bob\r\n", &key);
        let out = verify(&resolver_for(&s), &s.message).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].result, DkimResult::Pass);
        assert_eq!(out[0].domain, "example.com");
    }

    #[tokio::test]
    async fn ed25519_round_trip_passes() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let s = sign_ed25519(b" Alice <a@example.com>", b" Hello", b"Hi Bob\r\n", &key);
        let out = verify(&resolver_for(&s), &s.message).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].result, DkimResult::Pass);
    }

    #[tokio::test]
    async fn tampered_body_fails_on_body_hash() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut s = sign_ed25519(b" Alice <a@example.com>", b" Hi", b"original\r\n", &key);
        // Flip a body byte after signing: the bh= no longer matches.
        let pos = s.message.windows(8).position(|w| w == b"original").unwrap();
        s.message[pos] = b'X';
        let out = verify(&resolver_for(&s), &s.message).await;
        assert_eq!(out[0].result, DkimResult::Fail);
    }

    #[tokio::test]
    async fn tampered_header_fails_signature() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let s = sign_ed25519(b" Alice <a@example.com>", b" Hi", b"body\r\n", &key);
        // Alter a signed header (Subject) after signing.
        let mut message = s.message.clone();
        let pos = message.windows(3).position(|w| w == b"Hi\r").unwrap();
        message[pos] = b'Z';
        let out = verify(&resolver_for(&s), &message).await;
        assert_eq!(out[0].result, DkimResult::Fail);
    }

    #[tokio::test]
    async fn revoked_key_fails() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let s = sign_ed25519(b" Alice <a@example.com>", b" Hi", b"body\r\n", &key);
        let mut txt = BTreeMap::new();
        txt.insert(
            format!("{}._domainkey.{}", s.selector, s.domain),
            "v=DKIM1; k=ed25519; p=".to_string(), // empty p = revoked
        );
        let out = verify(&KeyResolver { txt }, &s.message).await;
        assert_eq!(out[0].result, DkimResult::Fail);
    }

    #[tokio::test]
    async fn missing_key_is_permerror() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let s = sign_ed25519(b" Alice <a@example.com>", b" Hi", b"body\r\n", &key);
        // Empty resolver: no key record published.
        let out = verify(
            &KeyResolver {
                txt: BTreeMap::new(),
            },
            &s.message,
        )
        .await;
        assert_eq!(out[0].result, DkimResult::PermError);
    }

    #[tokio::test]
    async fn no_signature_yields_empty() {
        let msg = b"From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n";
        let out = verify(
            &KeyResolver {
                txt: BTreeMap::new(),
            },
            msg,
        )
        .await;
        assert!(out.is_empty());
    }
}
