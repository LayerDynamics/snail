//! The durable outbound mail spool: a qmail-style on-disk queue of messages
//! awaiting relay, with retry scheduling that survives a process restart.
//!
//! Each queued message is two files in the spool directory:
//! - `<id>.eml`  — the raw message bytes ([`Message::to_bytes`]).
//! - `<id>.ctrl` — a line-based control record (envelope + retry state).
//!
//! Both are written temp-then-`rename` (atomic on the same filesystem); the
//! `.ctrl` file's presence marks a committed entry, so a crash between the two
//! writes leaves a stray `.eml` that [`OutboundSpool::due_now`] ignores. A
//! bounced (permanently failed) entry is moved into the `bounced/` subdirectory.
//!
//! There is no `serde` in the workspace, so the control format is hand-rolled:
//! one `key value` line per field, `rcpt` repeated per recipient.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mail::{Envelope, Mailbox, Message};

/// One queued message's metadata (the body lives in the sibling `.eml`).
#[derive(Debug, Clone)]
pub struct SpoolEntry {
    /// The queue id (also the filename stem); lexicographically time-ordered.
    pub id: String,
    /// SMTP reverse-path (`None` is the null sender `<>`).
    pub sender: Option<Mailbox>,
    /// SMTP forward-paths still to be relayed.
    pub recipients: Vec<Mailbox>,
    /// How many delivery attempts have already failed.
    pub attempts: u32,
    /// The earliest time this entry should next be attempted.
    pub next_attempt_at: SystemTime,
    /// When the entry was first enqueued.
    pub created_at: SystemTime,
}

impl SpoolEntry {
    /// Reconstruct the SMTP envelope for relaying this entry.
    #[must_use]
    pub fn envelope(&self) -> Envelope {
        Envelope::new(self.sender.clone(), self.recipients.clone())
    }
}

/// A durable, filesystem-backed outbound relay queue.
pub struct OutboundSpool {
    dir: PathBuf,
    counter: AtomicU64,
}

impl OutboundSpool {
    /// Open (creating if needed) the spool rooted at `dir`, plus its `bounced/`
    /// subdirectory.
    ///
    /// # Errors
    /// [`std::io::Error`] if the directories cannot be created.
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        fs::create_dir_all(dir.join("bounced"))?;
        let spool = Self {
            dir,
            counter: AtomicU64::new(0),
        };
        // Finish any bounce interrupted by a crash before serving (so a half-moved
        // entry is never stranded — see `bounce`).
        spool.recover_interrupted_bounces()?;
        Ok(spool)
    }

    /// Enqueue `message` for relay (attempts = 0, due immediately). Writes the
    /// `.eml` body first, then the `.ctrl` record, so the entry only becomes
    /// visible once fully committed.
    ///
    /// # Errors
    /// [`std::io::Error`] on a write failure.
    pub fn enqueue(&self, message: &Message) -> io::Result<String> {
        let id = self.new_id();
        let now = SystemTime::now();
        write_atomic(&self.eml_path(&id), &message.to_bytes())?;
        let ctrl = render_ctrl(&message.envelope, 0, now, now);
        write_atomic(&self.ctrl_path(&id), ctrl.as_bytes())?;
        Ok(id)
    }

    /// All entries whose `next_attempt_at` is at or before `now`, time-ordered.
    /// Stray `.eml`s without a committed `.ctrl`, and malformed control files,
    /// are skipped.
    ///
    /// # Errors
    /// [`std::io::Error`] if the directory cannot be read.
    pub fn due_now(&self, now: SystemTime) -> io::Result<Vec<SpoolEntry>> {
        let mut entries = Vec::new();
        for dirent in fs::read_dir(&self.dir)? {
            let path = dirent?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("ctrl") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if self.bouncing_marker(id).exists() {
                continue; // mid-bounce; recovery (run at open) relocates it
            }
            if !self.eml_path(id).exists() {
                continue; // incomplete entry (crash between the two writes)
            }
            let text = fs::read_to_string(&path)?;
            if let Ok(entry) = parse_ctrl(id, &text)
                && entry.next_attempt_at <= now
            {
                entries.push(entry);
            }
        }
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entries)
    }

    /// Reconstruct the [`Message`] for entry `id` from its `.eml` + `.ctrl`.
    ///
    /// # Errors
    /// [`std::io::Error`] if a file is missing or the record is malformed.
    pub fn load_message(&self, id: &str) -> io::Result<Message> {
        let eml = fs::read(self.eml_path(id))?;
        let ctrl = fs::read_to_string(self.ctrl_path(id))?;
        let entry = parse_ctrl(id, &ctrl).map_err(invalid)?;
        Message::parse(entry.envelope(), &eml).map_err(|e| invalid(e.to_string()))
    }

    /// Reschedule entry `id` after a transient failure: record the new attempt
    /// count and next-attempt time (preserving `created_at`).
    ///
    /// # Errors
    /// [`std::io::Error`] if the entry is missing or malformed.
    pub fn defer(&self, id: &str, attempts: u32, next_attempt_at: SystemTime) -> io::Result<()> {
        let text = fs::read_to_string(self.ctrl_path(id))?;
        let entry = parse_ctrl(id, &text).map_err(invalid)?;
        let updated = render_ctrl(
            &entry.envelope(),
            attempts,
            next_attempt_at,
            entry.created_at,
        );
        write_atomic(&self.ctrl_path(id), updated.as_bytes())
    }

    /// Permanently remove entry `id` (delivered).
    ///
    /// # Errors
    /// [`std::io::Error`] on a filesystem failure other than "not found".
    pub fn remove(&self, id: &str) -> io::Result<()> {
        remove_if_exists(&self.eml_path(id))?;
        remove_if_exists(&self.ctrl_path(id))?;
        Ok(())
    }

    /// Move entry `id` into `bounced/` (permanent failure / attempts exhausted),
    /// crash-safely.
    ///
    /// Moving two files is not atomic, so this drops a `<id>.bouncing` marker
    /// **first**, relocates the `.eml` then the `.ctrl`, then removes the marker.
    /// If the process crashes mid-move, the marker survives and
    /// [`Self::recover_interrupted_bounces`] (run at [`Self::open`]) finishes the
    /// relocation. Without this, a crash between the two renames stranded a `.ctrl`
    /// in the main dir whose `.eml` had already moved — which [`Self::due_now`]
    /// then skipped forever, silently losing the entry.
    ///
    /// # Errors
    /// [`std::io::Error`] on a write/rename failure.
    pub fn bounce(&self, id: &str) -> io::Result<()> {
        let marker = self.bouncing_marker(id);
        fs::write(&marker, id.as_bytes())?;
        self.relocate_to_bounced(id)?;
        remove_if_exists(&marker)
    }

    /// Complete any bounce left half-finished by a crash: for every `.bouncing`
    /// marker, relocate whichever of the pair still sits in the main dir into
    /// `bounced/`, then clear the marker.
    fn recover_interrupted_bounces(&self) -> io::Result<()> {
        for dirent in fs::read_dir(&self.dir)? {
            let path = dirent?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("bouncing") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            self.relocate_to_bounced(id)?;
            remove_if_exists(&path)?;
        }
        Ok(())
    }

    /// Move both files of entry `id` into `bounced/`. Idempotent: a file already
    /// moved (now missing from the main dir) is skipped, so this is safe to re-run
    /// during crash recovery.
    fn relocate_to_bounced(&self, id: &str) -> io::Result<()> {
        let bounced = self.dir.join("bounced");
        rename_if_exists(&self.eml_path(id), &bounced.join(format!("{id}.eml")))?;
        rename_if_exists(&self.ctrl_path(id), &bounced.join(format!("{id}.ctrl")))?;
        Ok(())
    }

    /// Delete bounced entries whose files have not been modified within
    /// `retention` (measured from `now`). Without this, `bounced/` grows without
    /// bound — the finding's other half. Returns the number of files removed.
    ///
    /// # Errors
    /// [`std::io::Error`] if the `bounced/` directory cannot be read.
    pub fn reap_bounced(&self, retention: Duration, now: SystemTime) -> io::Result<usize> {
        let bounced = self.dir.join("bounced");
        let mut removed = 0;
        for dirent in fs::read_dir(&bounced)? {
            let path = dirent?.path();
            if !path.is_file() {
                continue;
            }
            let modified = fs::metadata(&path).and_then(|m| m.modified());
            let aged_out = modified
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age >= retention);
            if aged_out {
                remove_if_exists(&path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn bouncing_marker(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.bouncing"))
    }

    fn new_id(&self) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{nanos:020}-{seq:06}")
    }

    fn eml_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.eml"))
    }

    fn ctrl_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.ctrl"))
    }
}

/// Exponential backoff between relay attempts: 60s, 120s, 240s, … capped at 1h.
#[must_use]
pub fn backoff(attempts: u32) -> Duration {
    const BASE: u64 = 60;
    const CAP: u64 = 3600;
    let secs = BASE.saturating_mul(1u64 << attempts.min(20)).min(CAP);
    Duration::from_secs(secs)
}

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

/// Write `bytes` to `path` atomically via a sibling temp file + rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("entry")
    ));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Rename `src` to `dst`, treating an already-moved (`NotFound`) `src` as success
/// so a relocation can be safely re-run during crash recovery.
fn rename_if_exists(src: &Path, dst: &Path) -> io::Result<()> {
    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn to_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn from_secs(s: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(s)
}

/// Serialize the control record.
fn render_ctrl(env: &Envelope, attempts: u32, next: SystemTime, created: SystemTime) -> String {
    let mut out = String::new();
    out.push_str(&format!("created {}\n", to_secs(created)));
    out.push_str(&format!("next {}\n", to_secs(next)));
    out.push_str(&format!("attempts {attempts}\n"));
    let from = env
        .sender
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    out.push_str(&format!("from {from}\n"));
    for rcpt in &env.recipients {
        out.push_str(&format!("rcpt {rcpt}\n"));
    }
    out
}

/// Parse a control record into a [`SpoolEntry`].
fn parse_ctrl(id: &str, text: &str) -> Result<SpoolEntry, String> {
    let (mut created, mut next, mut attempts) = (None, None, None);
    let mut sender = None;
    let mut recipients = Vec::new();
    for line in text.lines() {
        let (key, val) = line.split_once(' ').unwrap_or((line, ""));
        match key {
            "created" => created = Some(from_secs(val.parse().map_err(|_| "bad created")?)),
            "next" => next = Some(from_secs(val.parse().map_err(|_| "bad next")?)),
            "attempts" => attempts = Some(val.parse().map_err(|_| "bad attempts")?),
            "from" if !val.is_empty() => {
                sender = Some(Mailbox::parse(val).map_err(|e| e.to_string())?);
            }
            "rcpt" => recipients.push(Mailbox::parse(val).map_err(|e| e.to_string())?),
            _ => {}
        }
    }
    if recipients.is_empty() {
        return Err("control record has no recipients".into());
    }
    Ok(SpoolEntry {
        id: id.to_string(),
        sender,
        recipients,
        attempts: attempts.ok_or("missing attempts")?,
        next_attempt_at: next.ok_or("missing next")?,
        created_at: created.ok_or("missing created")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique throwaway spool directory under the OS temp dir.
    fn temp_spool() -> (OutboundSpool, PathBuf) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "snail-spool-test-{nanos}-{:?}",
            std::thread::current().id()
        ));
        (OutboundSpool::open(&dir).unwrap(), dir)
    }

    fn message() -> Message {
        Message::parse(
            Envelope::new(
                Some(Mailbox::parse("alice@example.com").unwrap()),
                vec![Mailbox::parse("bob@remote.test").unwrap()],
            ),
            b"Subject: queued\r\n\r\nbody text",
        )
        .unwrap()
    }

    #[test]
    fn enqueue_then_due_and_load_roundtrip() {
        let (spool, dir) = temp_spool();
        let id = spool.enqueue(&message()).unwrap();

        let due = spool
            .due_now(SystemTime::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].attempts, 0);
        assert_eq!(
            due[0].sender.as_ref().unwrap().to_string(),
            "alice@example.com"
        );
        assert_eq!(due[0].recipients[0].to_string(), "bob@remote.test");

        let msg = spool.load_message(&id).unwrap();
        assert_eq!(msg.subject(), Some("queued"));
        assert_eq!(msg.body, b"body text");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn defer_moves_entry_out_of_then_back_into_the_due_window() {
        let (spool, dir) = temp_spool();
        let id = spool.enqueue(&message()).unwrap();
        let now = SystemTime::now();

        spool
            .defer(&id, 1, now + Duration::from_secs(3600))
            .unwrap();
        assert!(
            spool.due_now(now).unwrap().is_empty(),
            "deferred entry must not be due"
        );

        let later = spool.due_now(now + Duration::from_secs(7200)).unwrap();
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].attempts, 1);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn remove_deletes_both_files() {
        let (spool, dir) = temp_spool();
        let id = spool.enqueue(&message()).unwrap();
        spool.remove(&id).unwrap();
        assert!(
            spool
                .due_now(SystemTime::now() + Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );
        assert!(!dir.join(format!("{id}.eml")).exists());
        assert!(!dir.join(format!("{id}.ctrl")).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bounce_relocates_into_bounced_dir() {
        let (spool, dir) = temp_spool();
        let id = spool.enqueue(&message()).unwrap();
        spool.bounce(&id).unwrap();
        assert!(
            spool
                .due_now(SystemTime::now() + Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );
        assert!(dir.join("bounced").join(format!("{id}.eml")).exists());
        assert!(dir.join("bounced").join(format!("{id}.ctrl")).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn interrupted_bounce_is_completed_on_reopen_not_stranded() {
        // Reproduce a crash *between* the two renames: the `.bouncing` marker is
        // down and the `.eml` has moved into bounced/, but the `.ctrl` is still in
        // the main dir. Before the fix, due_now skipped this `.ctrl` forever
        // (its `.eml` was "missing"), silently losing the entry.
        let (spool, dir) = temp_spool();
        let id = spool.enqueue(&message()).unwrap();
        drop(spool);

        let bounced = dir.join("bounced");
        fs::write(dir.join(format!("{id}.bouncing")), id.as_bytes()).unwrap();
        fs::rename(
            dir.join(format!("{id}.eml")),
            bounced.join(format!("{id}.eml")),
        )
        .unwrap();
        assert!(
            dir.join(format!("{id}.ctrl")).exists(),
            "the .ctrl is stranded in the main dir at crash time"
        );

        // Reopening recovers: the bounce is completed, nothing left in the main dir.
        let reopened = OutboundSpool::open(&dir).unwrap();
        assert!(
            reopened
                .due_now(SystemTime::now() + Duration::from_secs(1))
                .unwrap()
                .is_empty(),
            "a half-bounced entry must not be revived as a due entry"
        );
        assert!(bounced.join(format!("{id}.eml")).exists());
        assert!(bounced.join(format!("{id}.ctrl")).exists());
        assert!(!dir.join(format!("{id}.ctrl")).exists(), "ctrl relocated");
        assert!(
            !dir.join(format!("{id}.bouncing")).exists(),
            "marker cleared after recovery"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reap_bounced_removes_aged_entries_only() {
        let (spool, dir) = temp_spool();
        let id = spool.enqueue(&message()).unwrap();
        spool.bounce(&id).unwrap();
        let bounced = dir.join("bounced");
        assert!(bounced.join(format!("{id}.eml")).exists());

        // A long retention keeps a just-bounced entry; a zero retention reaps it.
        let kept = spool
            .reap_bounced(Duration::from_secs(3600), SystemTime::now())
            .unwrap();
        assert_eq!(kept, 0, "fresh bounced files are within retention");
        assert!(bounced.join(format!("{id}.eml")).exists());

        let reaped = spool
            .reap_bounced(Duration::ZERO, SystemTime::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(reaped, 2, "both .eml and .ctrl past retention are reaped");
        assert!(!bounced.join(format!("{id}.eml")).exists());
        assert!(!bounced.join(format!("{id}.ctrl")).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bounce_leaves_no_marker_behind() {
        let (spool, dir) = temp_spool();
        let id = spool.enqueue(&message()).unwrap();
        spool.bounce(&id).unwrap();
        assert!(
            !dir.join(format!("{id}.bouncing")).exists(),
            "a completed bounce must remove its crash-recovery marker"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn persists_across_reopen() {
        let (spool, dir) = temp_spool();
        let id = spool.enqueue(&message()).unwrap();
        drop(spool);

        // A fresh handle on the same directory sees the durable entry.
        let reopened = OutboundSpool::open(&dir).unwrap();
        let due = reopened
            .due_now(SystemTime::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_ctrl_rejects_malformed() {
        assert!(parse_ctrl("x", "garbage with no fields").is_err());
        assert!(parse_ctrl("x", "created 1\nnext 2\nattempts 0\nfrom \n").is_err()); // no rcpt
        assert!(
            parse_ctrl(
                "x",
                "created 1\nnext 2\nattempts notanumber\nrcpt b@y.com\n"
            )
            .is_err()
        );
    }

    #[test]
    fn backoff_is_monotonic_and_capped() {
        assert!(backoff(0) <= backoff(1));
        assert!(backoff(1) <= backoff(2));
        assert!(backoff(2) <= backoff(3));
        assert_eq!(backoff(100), Duration::from_secs(3600)); // capped
    }
}
