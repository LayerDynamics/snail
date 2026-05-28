//! SPF evaluation engine (RFC 7208 §4–§6): `check_host()` over a [`DnsResolver`],
//! with the mandatory DNS-lookup budget (≤10 querying terms, ≤2 void lookups),
//! CIDR matching, macro-expanded domain-specs, and recursive `include`/`redirect`.
//!
//! DNS-error classification note: the underlying [`DnsResolver`] collapses
//! "no records" and transient failures into one error, so this evaluator treats a
//! failed lookup as **no record** (the policy fetch → `None`; a sub-lookup → a
//! void no-match) rather than `TempError`. Distinguishing SERVFAIL/timeout to
//! return `TempError` is a future resolver enhancement; the variant is retained
//! in [`SpfResult`] for that and for callers (DMARC) that must handle it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::dns::DnsResolver;
use crate::spf::macro_expand::{MacroContext, expand};
use crate::spf::record::{Mechanism, Qualifier, SpfRecord};

/// The result of an SPF check (RFC 7208 §2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfResult {
    /// The client is authorized to send for the identity.
    Pass,
    /// The client is explicitly not authorized (`-all` / `-` qualifier matched).
    Fail,
    /// Weak "not authorized" (`~all`) — accept-but-mark.
    SoftFail,
    /// Explicitly no assertion (`?`).
    Neutral,
    /// The domain publishes no (usable) SPF record.
    None,
    /// A transient error prevented evaluation (reserved; see module note).
    TempError,
    /// The SPF record is syntactically invalid or exceeded a processing limit.
    PermError,
}

impl SpfResult {
    /// The lowercase token used in a `Received-SPF` header / by DMARC.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SpfResult::Pass => "pass",
            SpfResult::Fail => "fail",
            SpfResult::SoftFail => "softfail",
            SpfResult::Neutral => "neutral",
            SpfResult::None => "none",
            SpfResult::TempError => "temperror",
            SpfResult::PermError => "permerror",
        }
    }
}

/// Max DNS-querying terms per evaluation (RFC 7208 §4.6.4).
const MAX_LOOKUPS: u32 = 10;
/// Max void (empty/NXDOMAIN) lookups before `PermError` (§4.6.4).
const MAX_VOID: u32 = 2;
/// Max MX hosts / PTR names processed by one mechanism (§5.4, §5.5).
const MAX_HOSTS: usize = 10;

/// Evaluate SPF for a received message: is `ip` authorized to send mail for the
/// `MAIL FROM` identity `mail_from` (announced as `helo`)? An empty `mail_from`
/// (the null sender, e.g. a bounce) checks `postmaster@<helo>` per §2.4.
pub async fn evaluate(
    resolver: &dyn DnsResolver,
    ip: IpAddr,
    helo: &str,
    mail_from: &str,
) -> SpfResult {
    let (local, domain) = match mail_from.rsplit_once('@') {
        Some((l, d)) if !l.is_empty() && !d.is_empty() => (l.to_string(), d.to_string()),
        // Null/!addr sender: use postmaster@<helo> and evaluate the HELO domain.
        _ => ("postmaster".to_string(), helo.to_string()),
    };
    if domain.is_empty() {
        return SpfResult::None;
    }
    let mut ev = Evaluator {
        resolver,
        ip,
        sender_local: local,
        sender_domain: domain.clone(),
        helo: helo.to_string(),
        lookups: 0,
        void: 0,
    };
    ev.check_host(&domain).await
}

struct Evaluator<'a> {
    resolver: &'a dyn DnsResolver,
    ip: IpAddr,
    sender_local: String,
    sender_domain: String,
    helo: String,
    lookups: u32,
    void: u32,
}

impl Evaluator<'_> {
    /// RFC 7208 §4: fetch and evaluate the SPF record published at `domain`.
    async fn check_host(&mut self, domain: &str) -> SpfResult {
        // §4.3: fetch TXT; treat a lookup failure as "no record" (see module note).
        let txts = match self.resolver.lookup_txt(domain).await {
            Ok(txts) => txts,
            Err(_) => return SpfResult::None,
        };
        // §4.5: exactly one record may begin with the version token.
        let mut spf_records = txts.iter().filter(|t| {
            t.0.split_whitespace()
                .next()
                .is_some_and(SpfRecord::is_spf_version)
        });
        let Some(raw) = spf_records.next() else {
            return SpfResult::None;
        };
        if spf_records.next().is_some() {
            return SpfResult::PermError; // §4.5: multiple SPF records
        }
        let record = match SpfRecord::parse(&raw.0) {
            Ok(r) => r,
            Err(_) => return SpfResult::PermError, // §4.6: syntax error
        };

        for directive in &record.directives {
            match self.matches(&directive.mechanism, domain).await {
                MechOutcome::Match => return qualifier_result(directive.qualifier),
                MechOutcome::NoMatch => {}
                MechOutcome::Error(result) => return result,
            }
        }

        // §6.1: no directive matched — apply `redirect` if present.
        if let Some(redirect) = &record.redirect {
            if let Err(result) = self.charge_lookup() {
                return result;
            }
            let target = match self.expand(redirect, domain) {
                Ok(t) => t,
                Err(result) => return result,
            };
            // A redirect to a domain with no SPF record is a PermError (§6.1).
            return match Box::pin(self.check_host(&target)).await {
                SpfResult::None => SpfResult::PermError,
                other => other,
            };
        }

        // §4.7: default result when nothing matches and there is no redirect.
        SpfResult::Neutral
    }

    /// Evaluate one mechanism against the client IP. `current` is the domain being
    /// evaluated (the default target for `a`/`mx`/`ptr` and the `%{d}` macro).
    async fn matches(&mut self, mech: &Mechanism, current: &str) -> MechOutcome {
        match mech {
            Mechanism::All => MechOutcome::Match,
            Mechanism::Ip4 { net, prefix } => match self.ip {
                IpAddr::V4(c) => MechOutcome::from(cidr4(*net, *prefix, c)),
                IpAddr::V6(_) => MechOutcome::NoMatch,
            },
            Mechanism::Ip6 { net, prefix } => match self.ip {
                IpAddr::V6(c) => MechOutcome::from(cidr6(*net, *prefix, c)),
                IpAddr::V4(_) => MechOutcome::NoMatch,
            },
            Mechanism::A { domain, v4, v6 } => {
                self.a_match(domain.as_deref(), current, *v4, *v6).await
            }
            Mechanism::Mx { domain, v4, v6 } => {
                self.mx_match(domain.as_deref(), current, *v4, *v6).await
            }
            Mechanism::Include(spec) => self.include_match(spec, current).await,
            Mechanism::Exists(spec) => self.exists_match(spec, current).await,
            Mechanism::Ptr(domain) => self.ptr_match(domain.as_deref(), current).await,
        }
    }

    async fn a_match(
        &mut self,
        domain: Option<&str>,
        current: &str,
        v4: u8,
        v6: u8,
    ) -> MechOutcome {
        if let Err(r) = self.charge_lookup() {
            return MechOutcome::Error(r);
        }
        let target = match self.resolve_target(domain, current) {
            Ok(t) => t,
            Err(r) => return MechOutcome::Error(r),
        };
        let addrs = self.lookup_ip(&target).await;
        if addrs.is_empty()
            && let Err(r) = self.charge_void()
        {
            return MechOutcome::Error(r);
        }
        MechOutcome::from(addrs.iter().any(|a| ip_in_net(self.ip, *a, v4, v6)))
    }

    async fn mx_match(
        &mut self,
        domain: Option<&str>,
        current: &str,
        v4: u8,
        v6: u8,
    ) -> MechOutcome {
        if let Err(r) = self.charge_lookup() {
            return MechOutcome::Error(r);
        }
        let target = match self.resolve_target(domain, current) {
            Ok(t) => t,
            Err(r) => return MechOutcome::Error(r),
        };
        // A lookup failure is treated as "no MX" (see module note on error handling).
        let mxs = self.resolver.lookup_mx(&target).await.unwrap_or_default();
        if mxs.is_empty()
            && let Err(r) = self.charge_void()
        {
            return MechOutcome::Error(r);
        }
        // §5.4: at most 10 MX hosts are resolved to addresses.
        for mx in mxs.iter().take(MAX_HOSTS) {
            let addrs = self.lookup_ip(&mx.exchange).await;
            if addrs.iter().any(|a| ip_in_net(self.ip, *a, v4, v6)) {
                return MechOutcome::Match;
            }
        }
        MechOutcome::NoMatch
    }

    async fn include_match(&mut self, spec: &str, current: &str) -> MechOutcome {
        if let Err(r) = self.charge_lookup() {
            return MechOutcome::Error(r);
        }
        let target = match self.expand(spec, current) {
            Ok(t) => t,
            Err(r) => return MechOutcome::Error(r),
        };
        // §5.2: Pass → match; Fail/SoftFail/Neutral → no match; None → PermError;
        // Temp/PermError propagate.
        match Box::pin(self.check_host(&target)).await {
            SpfResult::Pass => MechOutcome::Match,
            SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral => MechOutcome::NoMatch,
            SpfResult::None => MechOutcome::Error(SpfResult::PermError),
            SpfResult::TempError => MechOutcome::Error(SpfResult::TempError),
            SpfResult::PermError => MechOutcome::Error(SpfResult::PermError),
        }
    }

    async fn exists_match(&mut self, spec: &str, current: &str) -> MechOutcome {
        if let Err(r) = self.charge_lookup() {
            return MechOutcome::Error(r);
        }
        let target = match self.expand(spec, current) {
            Ok(t) => t,
            Err(r) => return MechOutcome::Error(r),
        };
        // §5.7: matches if the name has any A record.
        let addrs = self.lookup_ip(&target).await;
        if addrs.is_empty()
            && let Err(r) = self.charge_void()
        {
            return MechOutcome::Error(r);
        }
        MechOutcome::from(!addrs.is_empty())
    }

    async fn ptr_match(&mut self, domain: Option<&str>, current: &str) -> MechOutcome {
        if let Err(r) = self.charge_lookup() {
            return MechOutcome::Error(r);
        }
        let target = match self.resolve_target(domain, current) {
            Ok(t) => t,
            Err(r) => return MechOutcome::Error(r),
        };
        let names = self
            .resolver
            .reverse_lookup(self.ip)
            .await
            .unwrap_or_default();
        if names.is_empty()
            && let Err(r) = self.charge_void()
        {
            return MechOutcome::Error(r);
        }
        // §5.5: a PTR name validates only if it forward-resolves back to the
        // client IP and lies within the target domain.
        let target_lc = target.to_ascii_lowercase();
        for name in names.iter().take(MAX_HOSTS) {
            let name_lc = name.0.to_ascii_lowercase();
            let within = name_lc == target_lc || name_lc.ends_with(&format!(".{target_lc}"));
            if within && self.lookup_ip(&name.0).await.contains(&self.ip) {
                return MechOutcome::Match;
            }
        }
        MechOutcome::NoMatch
    }

    /// Resolve a mechanism's target: the macro-expanded `domain` if present, else
    /// the current evaluation domain.
    fn resolve_target(
        &self,
        domain: Option<&str>,
        current: &str,
    ) -> std::result::Result<String, SpfResult> {
        match domain {
            Some(spec) => self.expand(spec, current),
            None => Ok(current.to_string()),
        }
    }

    /// Expand macros in `spec` against the current context. A malformed macro is a
    /// `PermError`.
    fn expand(&self, spec: &str, current: &str) -> std::result::Result<String, SpfResult> {
        let ctx = MacroContext {
            ip: self.ip,
            sender_local: &self.sender_local,
            sender_domain: &self.sender_domain,
            helo: &self.helo,
            domain: current,
        };
        expand(spec, &ctx).map_err(|_| SpfResult::PermError)
    }

    /// A/AAAA lookup that yields the raw addresses (empty on failure).
    async fn lookup_ip(&self, host: &str) -> Vec<IpAddr> {
        match self.resolver.lookup_ip(host).await {
            Ok(records) => records.iter().map(|r| r.0).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Charge one DNS-querying term against the budget (§4.6.4).
    fn charge_lookup(&mut self) -> std::result::Result<(), SpfResult> {
        self.lookups += 1;
        if self.lookups > MAX_LOOKUPS {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }

    /// Charge one void lookup against the budget (§4.6.4).
    fn charge_void(&mut self) -> std::result::Result<(), SpfResult> {
        self.void += 1;
        if self.void > MAX_VOID {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }
}

/// Outcome of evaluating a single mechanism.
enum MechOutcome {
    /// The mechanism matched — its qualifier decides the result.
    Match,
    /// The mechanism did not match — evaluation continues.
    NoMatch,
    /// Evaluation must terminate immediately with this result (limit/error).
    Error(SpfResult),
}

impl MechOutcome {
    fn from(matched: bool) -> Self {
        if matched {
            MechOutcome::Match
        } else {
            MechOutcome::NoMatch
        }
    }
}

fn qualifier_result(q: Qualifier) -> SpfResult {
    match q {
        Qualifier::Pass => SpfResult::Pass,
        Qualifier::Fail => SpfResult::Fail,
        Qualifier::SoftFail => SpfResult::SoftFail,
        Qualifier::Neutral => SpfResult::Neutral,
    }
}

/// Whether client IP `client` falls within `net`/`prefix`, matching address
/// families per RFC 7208 §5.6 (no IPv4/IPv6 cross-matching). `net` is a resolved
/// host address; the cidr lengths come from the mechanism's dual-cidr.
fn ip_in_net(client: IpAddr, net: IpAddr, v4: u8, v6: u8) -> bool {
    match (client, net) {
        (IpAddr::V4(c), IpAddr::V4(n)) => cidr4(n, v4, c),
        (IpAddr::V6(c), IpAddr::V6(n)) => cidr6(n, v6, c),
        _ => false,
    }
}

/// Whether `ip` is in the IPv4 network `net`/`prefix`.
fn cidr4(net: Ipv4Addr, prefix: u8, ip: Ipv4Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

/// Whether `ip` is in the IPv6 network `net`/`prefix`.
fn cidr6(net: Ipv6Addr, prefix: u8, ip: Ipv6Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let mask = u128::MAX << (128 - u32::from(prefix));
    (u128::from(net) & mask) == (u128::from(ip) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{AddressRecord, MxRecord, PtrRecord, TxtRecord};
    use crate::error::{NetworkError, Result};
    use async_trait::async_trait;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    #[derive(Default)]
    struct Mock {
        txt: BTreeMap<String, Vec<String>>,
        ip: BTreeMap<String, Vec<IpAddr>>,
        mx: BTreeMap<String, Vec<String>>,
        ptr: BTreeMap<IpAddr, Vec<String>>,
        fail_txt: bool,
    }

    #[async_trait]
    impl DnsResolver for Mock {
        async fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>> {
            Ok(self
                .mx
                .get(domain)
                .map(|v| {
                    v.iter()
                        .map(|e| MxRecord {
                            preference: 10,
                            exchange: e.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default())
        }
        async fn lookup_ip(&self, host: &str) -> Result<Vec<AddressRecord>> {
            Ok(self
                .ip
                .get(host)
                .map(|v| v.iter().copied().map(AddressRecord).collect())
                .unwrap_or_default())
        }
        async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>> {
            if self.fail_txt {
                return Err(NetworkError::Resolve {
                    name: name.into(),
                    reason: "boom".into(),
                });
            }
            Ok(self
                .txt
                .get(name)
                .map(|v| v.iter().cloned().map(TxtRecord).collect())
                .unwrap_or_default())
        }
        async fn reverse_lookup(&self, ip: IpAddr) -> Result<Vec<PtrRecord>> {
            Ok(self
                .ip_ptr(ip)
                .map(|v| v.iter().cloned().map(PtrRecord).collect())
                .unwrap_or_default())
        }
    }

    impl Mock {
        fn ip_ptr(&self, ip: IpAddr) -> Option<&Vec<String>> {
            self.ptr.get(&ip)
        }
        fn txt(mut self, name: &str, value: &str) -> Self {
            self.txt.insert(name.into(), vec![value.into()]);
            self
        }
        fn txt_multi(mut self, name: &str, values: &[&str]) -> Self {
            self.txt
                .insert(name.into(), values.iter().map(|s| (*s).into()).collect());
            self
        }
        fn ip(mut self, host: &str, addrs: &[&str]) -> Self {
            self.ip.insert(
                host.into(),
                addrs.iter().map(|a| a.parse().unwrap()).collect(),
            );
            self
        }
        fn mx(mut self, domain: &str, hosts: &[&str]) -> Self {
            self.mx
                .insert(domain.into(), hosts.iter().map(|h| (*h).into()).collect());
            self
        }
    }

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    async fn check(mock: &Mock, ip: IpAddr, from: &str) -> SpfResult {
        evaluate(mock, ip, "mail.sender.example", from).await
    }

    #[test]
    fn cidr_matching_edge_cases() {
        // /0 matches everything; /32 is exact; off-by-one bit fails.
        assert!(cidr4(
            "0.0.0.0".parse().unwrap(),
            0,
            "8.8.8.8".parse().unwrap()
        ));
        assert!(cidr4(
            "192.0.2.1".parse().unwrap(),
            32,
            "192.0.2.1".parse().unwrap()
        ));
        assert!(!cidr4(
            "192.0.2.0".parse().unwrap(),
            24,
            "192.0.3.1".parse().unwrap()
        ));
        assert!(cidr4(
            "192.0.2.0".parse().unwrap(),
            24,
            "192.0.2.255".parse().unwrap()
        ));
        // IPv4-mapped IPv6 must NOT match an ip4 mechanism (§5.6).
        assert!(!ip_in_net(
            "::ffff:192.0.2.1".parse().unwrap(),
            v4("192.0.2.1"),
            32,
            128
        ));
    }

    #[tokio::test]
    async fn ip4_pass_and_fail() {
        let m = Mock::default().txt("sender.example", "v=spf1 ip4:192.0.2.0/24 -all");
        assert_eq!(
            check(&m, v4("192.0.2.50"), "a@sender.example").await,
            SpfResult::Pass
        );
        assert_eq!(
            check(&m, v4("198.51.100.1"), "a@sender.example").await,
            SpfResult::Fail
        );
    }

    #[tokio::test]
    async fn no_record_is_none_and_multiple_is_permerror() {
        let none = Mock::default();
        assert_eq!(
            check(&none, v4("192.0.2.1"), "a@sender.example").await,
            SpfResult::None
        );
        let multi = Mock::default().txt_multi("sender.example", &["v=spf1 -all", "v=spf1 +all"]);
        assert_eq!(
            check(&multi, v4("192.0.2.1"), "a@sender.example").await,
            SpfResult::PermError
        );
    }

    #[tokio::test]
    async fn a_and_mx_mechanisms() {
        let m = Mock::default()
            .txt("sender.example", "v=spf1 a mx -all")
            .ip("sender.example", &["203.0.113.5"])
            .mx("sender.example", &["mx1.sender.example"])
            .ip("mx1.sender.example", &["203.0.113.9"]);
        assert_eq!(
            check(&m, v4("203.0.113.5"), "a@sender.example").await,
            SpfResult::Pass // matched `a`
        );
        assert_eq!(
            check(&m, v4("203.0.113.9"), "a@sender.example").await,
            SpfResult::Pass // matched `mx`
        );
        assert_eq!(
            check(&m, v4("203.0.113.99"), "a@sender.example").await,
            SpfResult::Fail
        );
    }

    #[tokio::test]
    async fn include_pass_and_none_is_permerror() {
        let m = Mock::default()
            .txt(
                "sender.example",
                "v=spf1 include:_spf.provider.example ~all",
            )
            .txt("_spf.provider.example", "v=spf1 ip4:203.0.113.0/24 -all");
        assert_eq!(
            check(&m, v4("203.0.113.7"), "a@sender.example").await,
            SpfResult::Pass
        );
        // include of a domain with no SPF record → PermError (§5.2).
        let broken = Mock::default().txt("sender.example", "v=spf1 include:missing.example ~all");
        assert_eq!(
            check(&broken, v4("203.0.113.7"), "a@sender.example").await,
            SpfResult::PermError
        );
    }

    #[tokio::test]
    async fn redirect_is_followed_when_nothing_matches() {
        let m = Mock::default()
            .txt("sender.example", "v=spf1 redirect=_spf.other.example")
            .txt("_spf.other.example", "v=spf1 ip4:192.0.2.0/24 -all");
        assert_eq!(
            check(&m, v4("192.0.2.9"), "a@sender.example").await,
            SpfResult::Pass
        );
        assert_eq!(
            check(&m, v4("10.0.0.1"), "a@sender.example").await,
            SpfResult::Fail
        );
    }

    #[tokio::test]
    async fn exceeding_the_lookup_budget_is_permerror() {
        // A self-referential include chain blows the 10-lookup budget.
        let mut m = Mock::default().txt("d0.example", "v=spf1 include:d1.example -all");
        for i in 1..=12 {
            m = m.txt(
                &format!("d{i}.example"),
                &format!("v=spf1 include:d{}.example -all", i + 1),
            );
        }
        assert_eq!(
            evaluate(&m, v4("192.0.2.1"), "helo", "a@d0.example").await,
            SpfResult::PermError
        );
    }

    #[tokio::test]
    async fn void_lookup_limit_is_permerror() {
        // Three `a` mechanisms whose targets resolve to nothing → 3 void lookups.
        let m = Mock::default().txt(
            "sender.example",
            "v=spf1 a:void1.example a:void2.example a:void3.example -all",
        );
        assert_eq!(
            check(&m, v4("192.0.2.1"), "a@sender.example").await,
            SpfResult::PermError
        );
    }

    #[tokio::test]
    async fn macro_in_exists_is_expanded_before_lookup() {
        // exists:%{i}... builds 1.2.3.4.list.example; only that name resolves.
        let m = Mock::default()
            .txt("sender.example", "v=spf1 exists:%{ir}.list.example -all")
            .ip("4.3.2.1.list.example", &["127.0.0.2"]);
        assert_eq!(
            check(&m, v4("1.2.3.4"), "a@sender.example").await,
            SpfResult::Pass
        );
    }

    #[tokio::test]
    async fn null_sender_checks_helo_domain() {
        // Empty MAIL FROM uses postmaster@<helo>; the HELO domain's SPF applies.
        let m = Mock::default().txt("mail.sender.example", "v=spf1 ip4:192.0.2.0/24 -all");
        assert_eq!(check(&m, v4("192.0.2.5"), "").await, SpfResult::Pass);
    }

    #[tokio::test]
    async fn failed_policy_lookup_is_none() {
        let m = Mock {
            fail_txt: true,
            ..Mock::default()
        };
        assert_eq!(
            check(&m, v4("192.0.2.1"), "a@sender.example").await,
            SpfResult::None
        );
    }
}
