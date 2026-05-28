//! A durable, append-only, **hash-chained** sink for security audit events.
//!
//! The in-memory ring ([`super::AuditLog`]) is bounded and volatile: an attacker
//! who triggers more than `capacity` events after a break-in rolls the evidence
//! out of the ring, and a crash loses the trail entirely. This sink complements
//! it with an append-only file in which every record carries a Blake2b hash that
//! chains it to its predecessor — so deleting, reordering, or modifying any
//! historical line breaks the chain and is detectable by [`DurableAuditSink::verify`].
//!
//! Each record is one line, tab-separated:
//! `<seq>\t<unix_secs>\t<event>\t<chain_hash_hex>`
//! where `chain_hash = Blake2b512(prev_hash_hex || "\n" || "<seq>\t<unix_secs>\t<event>")`.
//! The event encoding ([`super::AuditEvent::encode`]) is guaranteed free of tab
//! and newline, so the trailing hash is always recoverable with `rsplit_once('\t')`.
//!
//! Scope note: this provides durability + tamper-evidence. Size-based rotation of
//! the chain file is a future operational nicety (audit volume is low); it is not
//! implemented here so the chain stays a single verifiable sequence.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::{Blake2b512, Digest};

use crate::audit::AuditEvent;

/// The result of verifying a durable audit chain end-to-end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// Every record's hash links correctly to its predecessor.
    Valid {
        /// Number of records verified.
        records: u64,
    },
    /// The chain breaks at this 0-based line — tampering, truncation, or corruption.
    BrokenAt {
        /// The 0-based line index where verification first failed.
        line: u64,
    },
}

/// An append-only, hash-chained audit log file.
pub struct DurableAuditSink {
    path: PathBuf,
    state: Mutex<SinkState>,
}

struct SinkState {
    file: File,
    /// Hex hash of the most recently written record (the chain tip).
    prev_hash: String,
    /// Sequence number for the next record.
    seq: u64,
}

impl DurableAuditSink {
    /// Open (creating if needed) the chain file at `path`, recovering the chain
    /// tip — the last record's hash and the next sequence number — so appends
    /// continue the existing chain across a restart.
    ///
    /// # Errors
    /// [`std::io::Error`] if the parent directory or file cannot be created/opened.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let (prev_hash, seq) = match fs::read_to_string(&path) {
            Ok(existing) => tip(&existing),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (String::new(), 0),
            Err(e) => return Err(e),
        };
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(SinkState {
                file,
                prev_hash,
                seq,
            }),
        })
    }

    /// Append `event` as the next chained record, flushing and `fsync`ing before
    /// returning so a crash cannot lose an already-acknowledged security event.
    ///
    /// # Errors
    /// [`std::io::Error`] on a write/sync failure.
    pub fn append(&self, event: &AuditEvent) -> io::Result<()> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let payload = format!("{}\t{}\t{}", st.seq, ts, event.encode());
        let hash = chain_hash(&st.prev_hash, &payload);
        writeln!(st.file, "{payload}\t{hash}")?;
        st.file.flush()?;
        st.file.sync_data()?;
        st.prev_hash = hash;
        st.seq += 1;
        Ok(())
    }

    /// The chain file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-read the chain file at `path` and verify every record links to its
    /// predecessor. A missing file is an empty (valid) chain.
    ///
    /// # Errors
    /// [`std::io::Error`] if the file exists but cannot be read.
    pub fn verify(path: impl AsRef<Path>) -> io::Result<ChainStatus> {
        let text = match fs::read_to_string(path.as_ref()) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(ChainStatus::Valid { records: 0 });
            }
            Err(e) => return Err(e),
        };
        let mut prev = String::new();
        let mut records = 0u64;
        for (i, line) in text.lines().enumerate() {
            let Some((payload, hash)) = line.rsplit_once('\t') else {
                return Ok(ChainStatus::BrokenAt { line: i as u64 });
            };
            if chain_hash(&prev, payload) != hash {
                return Ok(ChainStatus::BrokenAt { line: i as u64 });
            }
            prev = hash.to_string();
            records += 1;
        }
        Ok(ChainStatus::Valid { records })
    }
}

/// Recover `(last_hash, next_seq)` from existing chain text. Reads the chain tip
/// from the last well-formed record; a trailing torn line (no tab) is ignored so
/// a crash mid-write does not poison the recovered tip.
fn tip(text: &str) -> (String, u64) {
    let mut prev = String::new();
    let mut seq = 0u64;
    for line in text.lines() {
        if let Some((payload, hash)) = line.rsplit_once('\t') {
            if let Some(s) = payload
                .split('\t')
                .next()
                .and_then(|s| s.parse::<u64>().ok())
            {
                seq = s + 1;
            }
            prev = hash.to_string();
        }
    }
    (prev, seq)
}

/// `Blake2b512(prev_hash_hex || "\n" || payload)`, hex-encoded.
fn chain_hash(prev_hash_hex: &str, payload: &str) -> String {
    let mut h = Blake2b512::new();
    h.update(prev_hash_hex.as_bytes());
    h.update(b"\n");
    h.update(payload.as_bytes());
    let digest = h.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "snail-audit-{tag}-{nanos}-{:?}.log",
            std::thread::current().id()
        ))
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn append_persists_reopens_and_continues_the_chain() {
        let path = temp_path("chain");
        {
            let sink = DurableAuditSink::open(&path).unwrap();
            sink.append(&AuditEvent::FirewallPaused).unwrap();
            sink.append(&AuditEvent::AuthFailure {
                user: "bob@example.com".into(),
                ip: ip(7),
            })
            .unwrap();
        } // dropped — simulates a restart

        // A fresh handle continues the same chain (seq resumes, prev_hash links).
        {
            let sink = DurableAuditSink::open(&path).unwrap();
            sink.append(&AuditEvent::FirewallResumed).unwrap();
        }

        // All three records verify as one unbroken chain.
        assert_eq!(
            DurableAuditSink::verify(&path).unwrap(),
            ChainStatus::Valid { records: 3 }
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn tampering_with_a_record_breaks_the_chain() {
        let path = temp_path("tamper");
        let sink = DurableAuditSink::open(&path).unwrap();
        sink.append(&AuditEvent::AuthSuccess {
            user: "alice".into(),
        })
        .unwrap();
        sink.append(&AuditEvent::RateLimited { ip: ip(9) }).unwrap();
        sink.append(&AuditEvent::FirewallPaused).unwrap();
        drop(sink);

        // Rewrite the first record's event field: the recomputed hash no longer
        // matches, and because each later hash chains off it, verification fails
        // at the tampered line.
        let original = fs::read_to_string(&path).unwrap();
        let tampered = original.replacen("auth_success user=alice", "auth_success user=mallory", 1);
        assert_ne!(original, tampered, "the test must actually mutate a record");
        fs::write(&path, &tampered).unwrap();

        assert_eq!(
            DurableAuditSink::verify(&path).unwrap(),
            ChainStatus::BrokenAt { line: 0 }
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn truncating_a_trailing_record_is_detected() {
        let path = temp_path("truncate");
        let sink = DurableAuditSink::open(&path).unwrap();
        sink.append(&AuditEvent::FirewallPaused).unwrap();
        sink.append(&AuditEvent::FirewallResumed).unwrap();
        drop(sink);

        // Corrupt the hash of the last record (a stand-in for in-place edits).
        let mut lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(ToString::to_string)
            .collect();
        let last = lines.last_mut().unwrap();
        last.pop(); // drop a hex digit from the trailing hash
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        assert_eq!(
            DurableAuditSink::verify(&path).unwrap(),
            ChainStatus::BrokenAt { line: 1 }
        );
        let _ = fs::remove_file(path);
    }
}
