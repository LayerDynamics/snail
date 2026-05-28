//! DMARC aggregate (`rua`) reporting (RFC 7489 §7.2): accumulate the per-message
//! DMARC results, then periodically emit a gzipped XML aggregate report to each
//! reporting domain's `rua` address via the outbound relay.
//!
//! Aggregation is in memory (a reporting window's worth of rows): reports are
//! best-effort, so losing an in-flight window on restart is acceptable. The XML
//! is hand-rolled (the workspace has no serde/XML dependency) against the RFC
//! 7489 Appendix C schema; gzip uses `flate2`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::Compression;
use flate2::write::GzEncoder;
use mail::{Envelope, Mailbox, Message};
use network::{AlignmentMode, DmarcPolicy, DmarcRecord, DmarcResult};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::server::{RelayAuthorization, Server};

/// The aggregation/reporting window (RFC 7489 default is 24h).
pub const REPORT_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Accumulates DMARC evaluation results into per-reporting-domain aggregate rows.
#[derive(Default)]
pub struct DmarcAggregator {
    state: Mutex<HashMap<String, DomainReport>>,
}

/// One reporting domain's accumulated rows, plus the policy that was published.
struct DomainReport {
    published: DmarcRecord,
    rua: String,
    rows: HashMap<RowKey, u64>,
}

/// The distinct dimensions of an aggregate row; identical rows are counted.
#[derive(Clone, PartialEq, Eq, Hash)]
struct RowKey {
    source_ip: IpAddr,
    header_from: String,
    disposition: String,
    dkim_eval_pass: bool,
    spf_eval_pass: bool,
    spf_domain: String,
    spf_result: String,
    dkim: Vec<(String, String)>,
}

/// A drained, ready-to-send report for one domain.
pub struct PendingReport {
    /// The reporting (policy) domain.
    pub domain: String,
    /// The published policy (for `<policy_published>`).
    pub published: DmarcRecord,
    /// The `rua` URI list as published.
    pub rua: String,
    /// The aggregated rows (each with its occurrence count).
    rows: Vec<(RowKey, u64)>,
}

impl DmarcAggregator {
    /// A new, empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one evaluated message into the aggregate. A no-op unless the domain
    /// published a DMARC record with a non-empty `rua` (nothing to report to).
    pub fn record(
        &self,
        result: &DmarcResult,
        source_ip: IpAddr,
        header_from: &str,
        spf_domain: &str,
        spf_result: &str,
        dkim: &[(String, String)],
    ) {
        let Some(published) = result.published.as_ref() else {
            return;
        };
        let Some(rua) = published.rua.clone().filter(|r| !r.is_empty()) else {
            return;
        };
        if result.policy_domain.is_empty() {
            return;
        }
        let key = RowKey {
            source_ip,
            header_from: header_from.to_ascii_lowercase(),
            disposition: result.disposition.as_str().to_string(),
            dkim_eval_pass: result.dkim_aligned,
            spf_eval_pass: result.spf_aligned,
            spf_domain: spf_domain.to_ascii_lowercase(),
            spf_result: spf_result.to_string(),
            dkim: dkim.to_vec(),
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = state
            .entry(result.policy_domain.clone())
            .or_insert_with(|| DomainReport {
                published: published.clone(),
                rua,
                rows: HashMap::new(),
            });
        *entry.rows.entry(key).or_insert(0) += 1;
    }

    /// Take and clear all accumulated reports (one per reporting domain).
    #[must_use]
    pub fn drain(&self) -> Vec<PendingReport> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *state)
            .into_iter()
            .map(|(domain, report)| PendingReport {
                domain,
                published: report.published,
                rua: report.rua,
                rows: report.rows.into_iter().collect(),
            })
            .collect()
    }
}

/// Build the aggregate-report email for `report` covering `[begin, end)` (Unix
/// seconds), addressed to the `rua` mailbox, from `host`. Returns `None` if the
/// `rua` has no usable address.
#[must_use]
pub fn build_report(
    host: &str,
    report: &PendingReport,
    begin: u64,
    end: u64,
    report_id: &str,
) -> Option<Message> {
    let rua = parse_rua(&report.rua)?;
    let xml = report_xml(host, report, begin, end, report_id);
    let gz = gzip(xml.as_bytes());
    let filename = format!("{host}!{}!{begin}!{end}.xml.gz", report.domain);

    let mut raw = Vec::new();
    push_line(&mut raw, &format!("From: dmarc-noreply@{host}"));
    push_line(&mut raw, &format!("To: <{rua}>"));
    push_line(
        &mut raw,
        &format!(
            "Subject: Report Domain: {} Submitter: {host} Report-ID: {report_id}",
            report.domain
        ),
    );
    push_line(&mut raw, "MIME-Version: 1.0");
    push_line(
        &mut raw,
        &format!("Content-Type: application/gzip; name=\"{filename}\""),
    );
    push_line(&mut raw, "Content-Transfer-Encoding: base64");
    push_line(
        &mut raw,
        &format!("Content-Disposition: attachment; filename=\"{filename}\""),
    );
    push_line(&mut raw, "");
    raw.extend_from_slice(wrap_base64(&BASE64.encode(&gz)).as_bytes());
    raw.extend_from_slice(b"\r\n");

    let from = Mailbox::parse(&format!("dmarc-noreply@{host}")).ok()?;
    let envelope = Envelope::new(Some(from), vec![rua]);
    Message::parse(envelope, &raw).ok()
}

/// Render the RFC 7489 Appendix C aggregate-report XML.
fn report_xml(host: &str, report: &PendingReport, begin: u64, end: u64, report_id: &str) -> String {
    let p = &report.published;
    let mut x = String::new();
    x.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<feedback>\r\n");
    x.push_str("  <report_metadata>\r\n");
    let _ = write!(x, "    <org_name>{}</org_name>\r\n", esc(host));
    let _ = write!(x, "    <email>dmarc-noreply@{}</email>\r\n", esc(host));
    let _ = write!(x, "    <report_id>{}</report_id>\r\n", esc(report_id));
    let _ = write!(
        x,
        "    <date_range><begin>{begin}</begin><end>{end}</end></date_range>\r\n"
    );
    x.push_str("  </report_metadata>\r\n");

    x.push_str("  <policy_published>\r\n");
    let _ = write!(x, "    <domain>{}</domain>\r\n", esc(&report.domain));
    let _ = write!(x, "    <adkim>{}</adkim>\r\n", align(p.adkim));
    let _ = write!(x, "    <aspf>{}</aspf>\r\n", align(p.aspf));
    let _ = write!(x, "    <p>{}</p>\r\n", policy(p.policy));
    if let Some(sp) = p.subdomain_policy {
        let _ = write!(x, "    <sp>{}</sp>\r\n", policy(sp));
    }
    let _ = write!(x, "    <pct>{}</pct>\r\n", p.pct);
    x.push_str("  </policy_published>\r\n");

    for (row, count) in &report.rows {
        x.push_str("  <record>\r\n    <row>\r\n");
        let _ = write!(x, "      <source_ip>{}</source_ip>\r\n", row.source_ip);
        let _ = write!(x, "      <count>{count}</count>\r\n");
        x.push_str("      <policy_evaluated>\r\n");
        let _ = write!(
            x,
            "        <disposition>{}</disposition>\r\n",
            esc(&row.disposition)
        );
        let _ = write!(
            x,
            "        <dkim>{}</dkim>\r\n",
            pass_fail(row.dkim_eval_pass)
        );
        let _ = write!(x, "        <spf>{}</spf>\r\n", pass_fail(row.spf_eval_pass));
        x.push_str("      </policy_evaluated>\r\n    </row>\r\n");
        let _ = write!(
            x,
            "    <identifiers><header_from>{}</header_from></identifiers>\r\n",
            esc(&row.header_from)
        );
        x.push_str("    <auth_results>\r\n");
        for (domain, result) in &row.dkim {
            let _ = write!(
                x,
                "      <dkim><domain>{}</domain><result>{}</result></dkim>\r\n",
                esc(domain),
                esc(result)
            );
        }
        let _ = write!(
            x,
            "      <spf><domain>{}</domain><result>{}</result></spf>\r\n",
            esc(&row.spf_domain),
            esc(&row.spf_result)
        );
        x.push_str("    </auth_results>\r\n  </record>\r\n");
    }
    x.push_str("</feedback>\r\n");
    x
}

/// gzip-compress `data` (RFC 7489 attachments are gzip).
fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    // Writing to an in-memory buffer cannot fail.
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}

/// Extract a usable mailbox from a `rua` URI list: the first `mailto:` entry,
/// minus any `!size` limit suffix.
fn parse_rua(rua: &str) -> Option<Mailbox> {
    rua.split(',').find_map(|entry| {
        let entry = entry.trim();
        let addr = entry
            .strip_prefix("mailto:")
            .or_else(|| entry.strip_prefix("MAILTO:"))?;
        let addr = addr.split('!').next().unwrap_or(addr).trim();
        Mailbox::parse(addr).ok()
    })
}

/// Wrap base64 text at 76 columns with CRLF (MIME).
fn wrap_base64(b64: &str) -> String {
    let bytes = b64.as_bytes();
    let mut out = String::with_capacity(b64.len() + b64.len() / 76 * 2);
    for chunk in bytes.chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push_str("\r\n");
    }
    out
}

fn push_line(out: &mut Vec<u8>, line: &str) {
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(b"\r\n");
}

fn align(mode: AlignmentMode) -> &'static str {
    match mode {
        AlignmentMode::Relaxed => "r",
        AlignmentMode::Strict => "s",
    }
}

fn policy(p: DmarcPolicy) -> &'static str {
    match p {
        DmarcPolicy::None => "none",
        DmarcPolicy::Quarantine => "quarantine",
        DmarcPolicy::Reject => "reject",
    }
}

fn pass_fail(pass: bool) -> &'static str {
    if pass { "pass" } else { "fail" }
}

/// Minimal XML text escaping.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Build the report-ID / window bounds and send every drained report through the
/// relay (the `rua` is remote, so `accept_inbound` queues it for outbound relay).
pub async fn flush_reports(server: &Server) {
    let reports = server.dmarc_aggregator().drain();
    if reports.is_empty() {
        return;
    }
    let end = unix_now();
    let begin = end.saturating_sub(REPORT_WINDOW.as_secs());
    for report in reports {
        let report_id = format!("{end}.{}", report.domain);
        match build_report(server.host_name(), &report, begin, end, &report_id) {
            Some(message) => {
                let _ = server.accept_inbound(message, RelayAuthorization::Permitted);
                tracing::info!(domain = %report.domain, rua = %report.rua, "queued DMARC aggregate report");
            }
            None => {
                tracing::warn!(domain = %report.domain, rua = %report.rua, "skipped DMARC report: unusable rua");
            }
        }
    }
}

/// Spawn the periodic DMARC aggregate-report worker: flush every `interval`
/// until `shutdown`. Reports relay outbound, so this should only be started when
/// outbound relay is configured.
pub fn spawn_report_worker(
    server: Arc<Server>,
    shutdown: Arc<Notify>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = shutdown.notified() => break,
                () = tokio::time::sleep(interval) => flush_reports(&server).await,
            }
        }
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use network::DmarcDisposition as Disp;
    use std::io::Read as _;

    fn record_with_rua(rua: &str) -> DmarcRecord {
        DmarcRecord::parse(&format!("v=DMARC1; p=reject; rua={rua}")).unwrap()
    }

    fn result(domain: &str, rec: DmarcRecord, disposition: Disp, spf_ok: bool) -> DmarcResult {
        DmarcResult {
            record_found: true,
            pass: spf_ok,
            spf_aligned: spf_ok,
            dkim_aligned: false,
            disposition,
            policy_domain: domain.to_string(),
            published: Some(rec),
        }
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, n))
    }

    #[test]
    fn aggregates_identical_rows_by_count() {
        let agg = DmarcAggregator::new();
        let rec = record_with_rua("mailto:dmarc@example.com");
        let res = result("example.com", rec, Disp::Reject, false);
        // Two identical messages and one from a different IP.
        agg.record(&res, ip(1), "example.com", "evil.test", "pass", &[]);
        agg.record(&res, ip(1), "example.com", "evil.test", "pass", &[]);
        agg.record(&res, ip(2), "example.com", "evil.test", "pass", &[]);

        let mut reports = agg.drain();
        assert_eq!(reports.len(), 1);
        let report = reports.pop().unwrap();
        assert_eq!(report.domain, "example.com");
        assert_eq!(report.rows.len(), 2, "two distinct source IPs");
        let total: u64 = report.rows.iter().map(|(_, c)| c).sum();
        assert_eq!(total, 3);
        // Draining cleared the aggregator.
        assert!(agg.drain().is_empty());
    }

    #[test]
    fn record_without_rua_is_ignored() {
        let agg = DmarcAggregator::new();
        let rec = DmarcRecord::parse("v=DMARC1; p=reject").unwrap(); // no rua
        let res = result("example.com", rec, Disp::Reject, false);
        agg.record(&res, ip(1), "example.com", "evil.test", "pass", &[]);
        assert!(agg.drain().is_empty());
    }

    #[test]
    fn parse_rua_extracts_mailbox_and_strips_size_limit() {
        assert_eq!(
            parse_rua("mailto:dmarc@example.com").unwrap().to_string(),
            "dmarc@example.com"
        );
        assert_eq!(
            parse_rua("mailto:agg@example.com!10m, mailto:other@x.test")
                .unwrap()
                .to_string(),
            "agg@example.com"
        );
        assert!(parse_rua("https://example.com/report").is_none());
    }

    #[test]
    fn report_xml_is_well_formed_and_gzip_round_trips() {
        let agg = DmarcAggregator::new();
        let rec = record_with_rua("mailto:dmarc@example.com");
        let res = result("example.com", rec, Disp::Quarantine, false);
        agg.record(
            &res,
            ip(7),
            "example.com",
            "evil.test",
            "pass",
            &[("other.test".into(), "fail".into())],
        );
        let report = agg.drain().pop().unwrap();

        let xml = report_xml("snail.example", &report, 1000, 2000, "rid-1");
        assert!(xml.contains("<feedback>"));
        assert!(xml.contains("<domain>example.com</domain>"));
        assert!(xml.contains("<p>reject</p>"));
        assert!(xml.contains("<source_ip>192.0.2.7</source_ip>"));
        assert!(xml.contains("<disposition>quarantine</disposition>"));
        assert!(xml.contains("<header_from>example.com</header_from>"));
        assert!(xml.contains("<spf><domain>evil.test</domain><result>pass</result></spf>"));
        assert!(xml.contains("<dkim><domain>other.test</domain><result>fail</result></dkim>"));

        // The gzip attachment round-trips back to the XML.
        let gz = gzip(xml.as_bytes());
        let mut decoded = String::new();
        GzDecoder::new(&gz[..])
            .read_to_string(&mut decoded)
            .unwrap();
        assert_eq!(decoded, xml);
    }

    #[test]
    fn build_report_targets_the_rua_with_a_gzip_attachment() {
        let agg = DmarcAggregator::new();
        let rec = record_with_rua("mailto:dmarc@reports.test");
        let res = result("example.com", rec, Disp::Reject, false);
        agg.record(&res, ip(9), "example.com", "evil.test", "pass", &[]);
        let report = agg.drain().pop().unwrap();

        let msg = build_report("snail.example", &report, 100, 200, "rid-9").unwrap();
        assert_eq!(msg.envelope.recipients[0].to_string(), "dmarc@reports.test");
        assert_eq!(
            msg.envelope.sender.as_ref().unwrap().to_string(),
            "dmarc-noreply@snail.example"
        );
        let text = String::from_utf8_lossy(&msg.to_bytes()).into_owned();
        assert!(text.contains("Content-Type: application/gzip"));
        assert!(text.contains("Report Domain: example.com"));
        assert!(text.contains("Content-Transfer-Encoding: base64"));
        assert!(text.contains("snail.example!example.com!100!200.xml.gz"));
    }

    #[test]
    fn xml_escapes_injection_attempts() {
        assert_eq!(esc("a<b>&\"'c"), "a&lt;b&gt;&amp;&quot;&apos;c");
    }

    #[tokio::test]
    async fn flush_reports_queues_a_report_to_the_rua_via_relay() {
        use crate::config::ServerConfig;
        use crate::spool::OutboundSpool;
        use network::{AddressRecord, MxRecord, PtrRecord, TxtRecord};

        // A no-op resolver — flush uses the stored published policy + rua, so it
        // performs no DNS itself; the resolver only enables outbound relay.
        struct NoDns;
        #[async_trait::async_trait]
        impl network::DnsResolver for NoDns {
            async fn lookup_mx(&self, _d: &str) -> network::Result<Vec<MxRecord>> {
                Ok(vec![])
            }
            async fn lookup_ip(&self, _h: &str) -> network::Result<Vec<AddressRecord>> {
                Ok(vec![])
            }
            async fn lookup_txt(&self, _n: &str) -> network::Result<Vec<TxtRecord>> {
                Ok(vec![])
            }
            async fn reverse_lookup(&self, _ip: IpAddr) -> network::Result<Vec<PtrRecord>> {
                Ok(vec![])
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "snail-dmarc-report-{}",
            unix_now() as u128 * 1000 + std::process::id() as u128
        ));
        let spool = Arc::new(OutboundSpool::open(&dir).unwrap());
        let server = Server::new(&ServerConfig::new(["example.com".to_string()]))
            .with_relay(Arc::new(NoDns), Arc::clone(&spool));

        let rec = record_with_rua("mailto:dmarc@reports.test");
        let res = result("example.com", rec, Disp::Reject, false);
        server
            .dmarc_aggregator()
            .record(&res, ip(1), "example.com", "evil.test", "fail", &[]);

        flush_reports(&server).await;

        // The aggregate report was enqueued for relay to the rua's (remote) domain.
        let due = spool
            .due_now(SystemTime::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(due.len(), 1, "one report should be queued");
        assert_eq!(due[0].recipients[0].to_string(), "dmarc@reports.test");
        assert!(
            due[0]
                .sender
                .as_ref()
                .unwrap()
                .to_string()
                .starts_with("dmarc-noreply@")
        );
        // The aggregator was drained.
        assert!(server.dmarc_aggregator().drain().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
