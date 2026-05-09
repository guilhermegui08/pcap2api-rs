// =============================================================================
// pcap2api-rs v2.1 — PCAP Threat Intelligence Analyser
//
// Changes from v2.0:
//   • Rate limiting now ONLY applied to remote API backends (AbuseIPDB,
//     VirusTotal, Shodan, IntelMQ-API). Local feed collectors never sleep.
//   • Feed download failures are reported with specific error context:
//     HTTP 403 → "access restricted (registration/key required)"
//     HTTP 429 → "rate limited by provider"
//     Network   → "network unreachable / timeout"
//   • Bambenek 403 is handled gracefully with a named fallback message.
//   • Richer terminal report:
//     - Asset type shown with a text badge [IP] [DOMAIN] [URL]
//     - Severity column (HIGH / MED / LOW) with color
//     - Source file column in the matches table
//     - Per-file summary before the consolidated report
//     - Feed status table at the end
//   • Richer CSV output:
//     - severity column
//     - count (how many times the observable appeared in the capture)
//     - context (dns-query, http-host, source, destination…)
//     - source_file
//     - details expanded into individual columns where stable
// =============================================================================

use anyhow::{Context, Result};
use clap::{Arg, ArgAction, Command};
use colored::*;
use csv::ReaderBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::time::sleep;
use url::Url;

// -----------------------------------------------------------------------------
// Async runtime
// -----------------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<()> {
    run().await
}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------
const VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "pcap2api";
const DEFAULT_CACHE_DIR: &str = ".cache/pcap2api";

lazy_static::lazy_static! {
    static ref PRIVATE_NETS: Vec<ipnet::IpNet> = {
        [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
            "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect()
    };

    static ref SERVICES: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        m.insert(21,    "ftp");         m.insert(22,    "ssh");
        m.insert(23,    "telnet");      m.insert(25,    "smtp");
        m.insert(53,    "dns");         m.insert(80,    "http");
        m.insert(110,   "pop3");        m.insert(143,   "imap");
        m.insert(443,   "https");       m.insert(445,   "smb");
        m.insert(3306,  "mysql");       m.insert(3389,  "rdp");
        m.insert(5432,  "postgresql");  m.insert(6379,  "redis");
        m.insert(8080,  "http-alt");    m.insert(8443,  "https-alt");
        m.insert(27017, "mongodb");     m.insert(6667,  "irc");
        m.insert(4444,  "metasploit");  m.insert(1433,  "mssql");
        m.insert(5900,  "vnc");
        m
    };

    static ref SUSPICIOUS_PORTS: HashSet<u16> = {
        [4444u16, 1337, 31337, 12345, 54321, 6666, 6667, 6668, 1080, 9050, 9051]
            .iter()
            .cloned()
            .collect()
    };

    static ref HTTP_CLIENT: reqwest::Client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(format!("{}/{}", TOOL_NAME, VERSION))
        .build()
        .unwrap();
}

// =============================================================================
// 1. Data Models
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Observable {
    pub kind: String, // "ip" | "domain" | "url" | "port"
    pub value: String,
    pub context: String, // dns-query, http-host, source, destination, …
    pub source_file: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMatch {
    pub observable: Observable,
    pub ti_source: String,
    pub classification_type: String,
    pub classification_taxonomy: String,
    pub confidence: f64,
    pub details: Value,
}

impl ThreatMatch {
    pub fn severity(&self) -> &'static str {
        if self.confidence >= 0.75 {
            "HIGH"
        } else if self.confidence >= 0.45 {
            "MED"
        } else {
            "LOW"
        }
    }
}

/// Describes why a feed failed to load — lets us give targeted advice.
#[derive(Debug)]
enum FeedError {
    Http403,         // access restricted
    Http429,         // rate limited by provider
    HttpOther(u16),  // other HTTP error
    Network(String), // connection / timeout
}

impl FeedError {
    fn message(&self, feed_name: &str) -> String {
        match self {
            FeedError::Http403 => format!(
                "[WARN] {}: HTTP 403 — access restricted. \
                         This feed now requires registration or an API key.",
                feed_name
            ),
            FeedError::Http429 => format!(
                "[WARN] {}: HTTP 429 — rate limited by provider. \
                         Try again later or reduce --refresh-feeds frequency.",
                feed_name
            ),
            FeedError::HttpOther(code) => {
                format!("[WARN] {}: HTTP {} from feed server.", feed_name, code)
            }
            FeedError::Network(e) => format!("[WARN] {}: network error — {}.", feed_name, e),
        }
    }
}

// =============================================================================
// 2. Utilities
// =============================================================================

fn is_private_ip(addr: &str) -> bool {
    addr.parse::<IpAddr>()
        .map(|ip| PRIVATE_NETS.iter().any(|net| net.contains(&ip)))
        .unwrap_or(false)
}

fn is_valid_domain(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    if name.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    lazy_static::lazy_static! {
        static ref DOMAIN_RE: Regex = Regex::new(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        ).unwrap();
    }
    DOMAIN_RE.is_match(name.trim_end_matches('.'))
}

fn extract_urls_from_payload(payload: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();
    if let Ok(text) = std::str::from_utf8(payload) {
        lazy_static::lazy_static! {
            static ref HOST_RE: Regex = Regex::new(r"Host:\s*([^\r\n]+)").unwrap();
            static ref REQ_RE:  Regex = Regex::new(r"(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)").unwrap();
            static ref URL_RE:  Regex = Regex::new(r#"https?://[^\s"'<>]+"#).unwrap();
        }
        if let (Some(hc), Some(rc)) = (HOST_RE.captures(text), REQ_RE.captures(text)) {
            urls.push(format!("http://{}{}", hc[1].trim(), rc[1].trim()));
        }
        for cap in URL_RE.captures_iter(text) {
            urls.push(cap[0].to_string());
        }
    }
    urls
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn kind_badge(kind: &str) -> ColoredString {
    match kind {
        "ip" => " IP  ".on_blue().white().bold(),
        "domain" => " DOM ".on_magenta().white().bold(),
        "url" => " URL ".on_cyan().black().bold(),
        "port" => " PORT".on_yellow().black().bold(),
        _ => kind.normal(),
    }
}

fn severity_badge(conf: f64) -> ColoredString {
    if conf >= 0.75 {
        " HIGH ".on_red().white().bold()
    } else if conf >= 0.45 {
        "  MED ".on_yellow().black().bold()
    } else {
        "  LOW ".on_bright_black().white()
    }
}

// =============================================================================
// 3. Feed Cache
// =============================================================================

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    ts: u64,
    payload: Value,
}

struct FeedCache {
    dir: PathBuf,
}

impl FeedCache {
    fn new(dir: PathBuf) -> Self {
        fs::create_dir_all(&dir).unwrap_or(());
        FeedCache { dir }
    }

    fn path(&self, feed_id: &str) -> PathBuf {
        let safe = feed_id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_");
        self.dir.join(format!("{}.json", safe))
    }

    fn get(&self, feed_id: &str, ttl: u64) -> Option<Value> {
        let p = self.path(feed_id);
        if !p.exists() {
            return None;
        }
        let data: CacheEntry = serde_json::from_str(&fs::read_to_string(p).ok()?).ok()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now - data.ts < ttl {
            Some(data.payload)
        } else {
            None
        }
    }

    fn set(&self, feed_id: &str, payload: &Value) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = fs::write(
            self.path(feed_id),
            serde_json::to_string_pretty(&CacheEntry {
                ts: now,
                payload: payload.clone(),
            })
            .unwrap(),
        );
    }

    fn age_str(&self, feed_id: &str) -> String {
        let p = self.path(feed_id);
        if !p.exists() {
            return "no cache".to_string();
        }
        if let Ok(s) = fs::read_to_string(&p) {
            if let Ok(e) = serde_json::from_str::<CacheEntry>(&s) {
                let age = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - e.ts;
                return if age < 120 {
                    format!("{}s ago", age)
                } else if age < 7200 {
                    format!("{}m ago", age / 60)
                } else {
                    format!("{}h ago", age / 3600)
                };
            }
        }
        "unknown".to_string()
    }
}

// =============================================================================
// 4. PCAP Extraction (streaming via libpcap)
// =============================================================================

use pcap::Capture;

fn extract_observables_from_pcap(
    path: &Path,
    include_private: bool,
    kinds: &HashSet<String>,
) -> Result<Vec<Observable>> {
    let mut cap =
        Capture::from_file(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut map: HashMap<String, Observable> = HashMap::new();

    while let Ok(pkt) = cap.next_packet() {
        process_packet(&pkt, path, &mut map);
    }

    let mut list: Vec<Observable> = map.into_values().collect();
    list.retain(|o| kinds.contains(&o.kind));
    if !include_private {
        list.retain(|o| o.kind != "ip" || !is_private_ip(&o.value));
    }
    Ok(list)
}

fn add_obs(
    map: &mut HashMap<String, Observable>,
    kind: &str,
    value: &str,
    context: &str,
    src: &Path,
) {
    let key = format!("{}:{}", kind, value);
    map.entry(key)
        .and_modify(|e| e.count += 1)
        .or_insert_with(|| Observable {
            kind: kind.to_string(),
            value: value.to_string(),
            context: context.to_string(),
            source_file: src.display().to_string(),
            count: 1,
        });
}

fn process_packet(pkt: &pcap::Packet, src: &Path, map: &mut HashMap<String, Observable>) {
    let eth = pkt.data;
    if eth.len() < 14 {
        return;
    }
    let eth_type = u16::from_be_bytes([eth[12], eth[13]]);
    if eth_type != 0x0800 {
        return;
    } // IPv4 only

    let ip = &eth[14..];
    if ip.len() < 20 {
        return;
    }

    let src_ip = std::net::Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = std::net::Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let proto = ip[9];
    let ihl = ((ip[0] & 0x0F) as usize) * 4;

    add_obs(map, "ip", &src_ip.to_string(), "source", src);
    add_obs(map, "ip", &dst_ip.to_string(), "destination", src);

    let tp_offset = 14 + ihl;
    if eth.len() < tp_offset + 4 {
        return;
    }
    let tp = &eth[tp_offset..];

    if proto == 6 && tp.len() >= 20 {
        // TCP
        let dport = u16::from_be_bytes([tp[2], tp[3]]);
        let svc_ctx = if SUSPICIOUS_PORTS.contains(&dport) {
            "suspicious"
        } else {
            SERVICES.get(&dport).copied().unwrap_or("tcp")
        };
        add_obs(map, "port", &dport.to_string(), svc_ctx, src);

        let tcp_hlen = ((tp[12] >> 4) as usize) * 4;
        let payload_off = tp_offset + tcp_hlen;
        if payload_off < eth.len() {
            for url in extract_urls_from_payload(&eth[payload_off..]) {
                add_obs(map, "url", &url, "http", src);
                if let Ok(parsed) = Url::parse(&url) {
                    if let Some(host) = parsed.host_str() {
                        if is_valid_domain(host) {
                            add_obs(map, "domain", host, "http-host", src);
                        }
                    }
                }
            }
        }
    } else if proto == 17 && tp.len() >= 8 {
        // UDP
        let dport = u16::from_be_bytes([tp[2], tp[3]]);
        let svc_ctx = if SUSPICIOUS_PORTS.contains(&dport) {
            "suspicious"
        } else {
            SERVICES.get(&dport).copied().unwrap_or("udp")
        };
        add_obs(map, "port", &dport.to_string(), svc_ctx, src);

        if dport == 53 && tp.len() > 8 {
            if let Ok(dns) = dns_parser::Packet::parse(&tp[8..]) {
                for q in dns.questions {
                    let name = q.qname.to_string();
                    if is_valid_domain(&name) {
                        add_obs(map, "domain", &name, "dns-query", src);
                    }
                }
            }
        }
    }
}

// =============================================================================
// 5. Threat Intelligence Backend trait
// =============================================================================

#[async_trait::async_trait]
trait ThreatIntelBackend: Send + Sync {
    fn name(&self) -> &'static str;
    /// Returns true for backends that make network API calls (need rate limiting).
    fn is_remote_api(&self) -> bool {
        false
    }
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit>;
    async fn check_domain(&self, domain: &str) -> Vec<ThreatHit>;
    async fn check_url(&self, url: &str) -> Vec<ThreatHit>;
}

#[derive(Debug, Clone)]
struct ThreatHit {
    source: String,
    classification_type: String,
    classification_taxonomy: String,
    confidence: f64,
    details: Value,
}

// =============================================================================
// 6. Local Feed Collectors
// =============================================================================

#[derive(Clone, Default, Serialize, Deserialize)]
struct FeedData {
    ips: HashSet<String>,
    domains: HashSet<String>,
    urls: HashSet<String>,
}

struct FeedCollector {
    name: &'static str,
    feed_id: &'static str,
    feed_url: String,
    ttl: u64,
    cache: Arc<FeedCache>,
    force_refresh: bool,
    verbose: bool,
    // Classification defaults per observable type
    ip_type: &'static str,
    ip_tax: &'static str,
    ip_conf: f64,
    dom_type: &'static str,
    dom_tax: &'static str,
    dom_conf: f64,
    url_type: &'static str,
    url_tax: &'static str,
    url_conf: f64,
    parse_fn: Box<dyn Fn(&str) -> FeedData + Send + Sync>,
    data: Arc<Mutex<Option<FeedData>>>,
}

impl FeedCollector {
    #[allow(clippy::too_many_arguments)]
    fn new<F>(
        name: &'static str,
        feed_id: &'static str,
        feed_url: String,
        ttl: u64,
        cache: Arc<FeedCache>,
        force_refresh: bool,
        verbose: bool,
        ip_type: &'static str,
        ip_tax: &'static str,
        ip_conf: f64,
        dom_type: &'static str,
        dom_tax: &'static str,
        dom_conf: f64,
        url_type: &'static str,
        url_tax: &'static str,
        url_conf: f64,
        parse: F,
    ) -> Self
    where
        F: Fn(&str) -> FeedData + Send + Sync + 'static,
    {
        FeedCollector {
            name,
            feed_id,
            feed_url,
            ttl,
            cache,
            force_refresh,
            verbose,
            ip_type,
            ip_tax,
            ip_conf,
            dom_type,
            dom_tax,
            dom_conf,
            url_type,
            url_tax,
            url_conf,
            parse_fn: Box::new(parse),
            data: Arc::new(Mutex::new(None)),
        }
    }

    async fn load(&self) -> FeedData {
        {
            let g = self.data.lock().await;
            if let Some(ref d) = *g {
                return d.clone();
            }
        }

        // Cache hit?
        if !self.force_refresh {
            if let Some(cached) = self.cache.get(self.feed_id, self.ttl) {
                if self.verbose {
                    eprintln!(
                        "  [cache] {} ({})",
                        self.name,
                        self.cache.age_str(self.feed_id)
                    );
                }
                let d: FeedData = serde_json::from_value(cached).unwrap_or_default();
                *self.data.lock().await = Some(d.clone());
                return d;
            }
        }

        if self.verbose {
            eprintln!("  [fetch] {} <- {}", self.name, self.feed_url);
        }

        // Download with explicit error categorisation
        let resp = HTTP_CLIENT.get(&self.feed_url).send().await;
        let raw = match resp {
            Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
            Ok(r) => {
                let err = match r.status().as_u16() {
                    403 => FeedError::Http403,
                    429 => FeedError::Http429,
                    c => FeedError::HttpOther(c),
                };
                eprintln!("{}", err.message(self.name).yellow());
                // Fall back to stale cache if available
                let stale = self.cache.get(self.feed_id, u64::MAX);
                if let Some(v) = stale {
                    eprintln!(
                        "  [info]  {} using stale cache ({})",
                        self.name,
                        self.cache.age_str(self.feed_id)
                    );
                    let d: FeedData = serde_json::from_value(v).unwrap_or_default();
                    *self.data.lock().await = Some(d.clone());
                    return d;
                }
                *self.data.lock().await = Some(FeedData::default());
                return FeedData::default();
            }
            Err(e) => {
                let err = FeedError::Network(e.to_string());
                eprintln!("{}", err.message(self.name).yellow());
                let stale = self.cache.get(self.feed_id, u64::MAX);
                if let Some(v) = stale {
                    eprintln!(
                        "  [info]  {} using stale cache ({})",
                        self.name,
                        self.cache.age_str(self.feed_id)
                    );
                    let d: FeedData = serde_json::from_value(v).unwrap_or_default();
                    *self.data.lock().await = Some(d.clone());
                    return d;
                }
                *self.data.lock().await = Some(FeedData::default());
                return FeedData::default();
            }
        };

        let parsed = (self.parse_fn)(&raw);

        if self.verbose {
            eprintln!(
                "  [ok]    {} — ips:{} domains:{} urls:{}",
                self.name,
                parsed.ips.len(),
                parsed.domains.len(),
                parsed.urls.len()
            );
        }

        if let Ok(v) = serde_json::to_value(&parsed) {
            self.cache.set(self.feed_id, &v);
        }
        *self.data.lock().await = Some(parsed.clone());
        parsed
    }

    fn hit(&self, ctype: &str, ctax: &str, conf: f64, extra: Value) -> ThreatHit {
        ThreatHit {
            source: self.name.to_string(),
            classification_type: ctype.to_string(),
            classification_taxonomy: ctax.to_string(),
            confidence: conf,
            details: extra,
        }
    }
}

#[async_trait::async_trait]
impl ThreatIntelBackend for FeedCollector {
    fn name(&self) -> &'static str {
        self.name
    }
    fn is_remote_api(&self) -> bool {
        false
    } // local feed — no rate limiting needed

    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        if self.ip_type.is_empty() {
            return vec![];
        }
        let data = self.load().await;
        // Exact set membership (O(1))
        if data.ips.contains(ip) {
            return vec![self.hit(
                self.ip_type,
                self.ip_tax,
                self.ip_conf,
                json!({ "feed": self.name, "matched": ip }),
            )];
        }
        // CIDR containment for feeds that store network ranges
        if let Ok(target) = ip.parse::<IpAddr>() {
            for entry in &data.ips {
                if let Ok(net) = entry.parse::<ipnet::IpNet>() {
                    if net.contains(&target) {
                        return vec![self.hit(
                            self.ip_type,
                            self.ip_tax,
                            self.ip_conf,
                            json!({ "feed": self.name, "matched_cidr": entry }),
                        )];
                    }
                }
            }
        }
        vec![]
    }

    async fn check_domain(&self, domain: &str) -> Vec<ThreatHit> {
        if self.dom_type.is_empty() {
            return vec![];
        }
        let data = self.load().await;
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 0..parts.len() {
            let candidate = parts[i..].join(".");
            if data.domains.contains(&candidate) {
                return vec![self.hit(
                    self.dom_type,
                    self.dom_tax,
                    self.dom_conf,
                    json!({ "feed": self.name, "matched": candidate }),
                )];
            }
        }
        vec![]
    }

    async fn check_url(&self, url: &str) -> Vec<ThreatHit> {
        if self.url_type.is_empty() {
            return vec![];
        }
        let data = self.load().await;
        // Exact match first (O(1)), then prefix scan
        if data.urls.contains(url) {
            return vec![self.hit(
                self.url_type,
                self.url_tax,
                self.url_conf,
                json!({ "feed": self.name, "matched": url }),
            )];
        }
        for feed_url in &data.urls {
            if url.starts_with(feed_url.as_str()) {
                return vec![self.hit(
                    self.url_type,
                    self.url_tax,
                    self.url_conf,
                    json!({ "feed": self.name, "matched": feed_url }),
                )];
            }
        }
        vec![]
    }
}

// =============================================================================
// 6a. Feed parsers (unchanged from v2.0, kept compact)
// =============================================================================

fn split_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut in_q = false;
    for (i, b) in line.bytes().enumerate() {
        match b {
            b'"' => in_q = !in_q,
            b',' if !in_q => {
                fields.push(&line[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    fields.push(&line[start..]);
    fields
}

fn urlhaus_parse(raw: &str) -> FeedData {
    let mut d = FeedData::default();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() < 3 {
            continue;
        }
        let url = fields[2].trim_matches('"').trim();
        if url.eq_ignore_ascii_case("url") {
            continue;
        }
        if url.starts_with("http") {
            d.urls.insert(url.to_string());
            if let Ok(parsed) = Url::parse(url) {
                if let Some(host) = parsed.host_str() {
                    if let Ok(ip) = host.parse::<IpAddr>() {
                        if !is_private_ip(&ip.to_string()) {
                            d.ips.insert(ip.to_string());
                        }
                    } else if is_valid_domain(host) {
                        d.domains.insert(host.to_lowercase());
                    }
                }
            }
        }
    }
    d
}

fn feodo_parse(raw: &str) -> FeedData {
    let mut d = FeedData::default();
    let mut header_seen = false;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !header_seen {
            header_seen = true;
            continue;
        }
        let fields: Vec<&str> = line.splitn(6, ',').collect();
        if fields.len() < 2 {
            continue;
        }
        let ip = fields[1].trim().trim_matches('"');
        if ip.parse::<IpAddr>().is_ok() && !is_private_ip(ip) {
            d.ips.insert(ip.to_string());
        }
    }
    d
}

fn phishtank_parse(raw: &str) -> FeedData {
    let mut d = FeedData::default();
    let mut rdr = ReaderBuilder::new()
        .flexible(true)
        .from_reader(raw.as_bytes());
    let headers = match rdr.headers() {
        Ok(h) => h.clone(),
        Err(_) => return d,
    };
    let url_col = match headers.iter().position(|h| h.eq_ignore_ascii_case("url")) {
        Some(c) => c,
        None => return d,
    };
    for rec in rdr.records().flatten() {
        if let Some(url) = rec.get(url_col) {
            let url = url.trim();
            if url.starts_with("http") {
                d.urls.insert(url.to_string());
                if let Ok(p) = Url::parse(url) {
                    if let Some(host) = p.host_str() {
                        if is_valid_domain(host) {
                            d.domains.insert(host.to_lowercase());
                        } else if let Ok(ip) = host.parse::<IpAddr>() {
                            if !is_private_ip(&ip.to_string()) {
                                d.ips.insert(ip.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    d
}

fn bambenek_parse(raw: &str) -> FeedData {
    let mut d = FeedData::default();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let domain = line.split(',').next().unwrap_or("").trim();
        if is_valid_domain(domain) {
            d.domains.insert(domain.to_lowercase());
        }
    }
    d
}

fn blocklist_de_parse(raw: &str) -> FeedData {
    let mut d = FeedData::default();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.parse::<IpAddr>().is_ok() && !is_private_ip(line) {
            d.ips.insert(line.to_string());
        }
    }
    d
}

fn emerging_threats_parse(raw: &str) -> FeedData {
    // Store CIDRs as strings — containment is checked in check_ip via ipnet
    let mut d = FeedData::default();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(net) = line.parse::<ipnet::IpNet>() {
            if !is_private_ip(&net.addr().to_string()) {
                d.ips.insert(net.to_string());
            }
        } else if let Ok(ip) = line.parse::<IpAddr>() {
            if !is_private_ip(&ip.to_string()) {
                d.ips.insert(ip.to_string());
            }
        }
    }
    d
}

fn otx_parse(raw: &str) -> FeedData {
    let mut d = FeedData::default();
    if let Ok(inds) = serde_json::from_str::<Vec<Value>>(raw) {
        for ind in inds {
            let t = ind.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let v = ind
                .get("indicator")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if v.is_empty() {
                continue;
            }
            match t {
                "IPv4" | "IPv6" => {
                    if !is_private_ip(v) {
                        d.ips.insert(v.to_string());
                    }
                }
                "domain" | "FQDN" | "hostname" => {
                    if is_valid_domain(v) {
                        d.domains.insert(v.to_lowercase());
                    }
                }
                "URL" if v.starts_with("http") => {
                    d.urls.insert(v.to_string());
                }
                _ => {}
            }
        }
    }
    d
}

// OTX collector (paginated API download)
struct OtxCollector {
    api_key: String,
    cache: Arc<FeedCache>,
    force_refresh: bool,
    verbose: bool,
    data: Arc<Mutex<Option<FeedData>>>,
}

impl OtxCollector {
    const FEED_ID: &'static str = "otx_alienvault";
    const TTL: u64 = 7200;

    async fn load(&self) -> FeedData {
        {
            let g = self.data.lock().await;
            if let Some(ref d) = *g {
                return d.clone();
            }
        }
        if !self.force_refresh {
            if let Some(cached) = self.cache.get(Self::FEED_ID, Self::TTL) {
                if self.verbose {
                    eprintln!(
                        "  [cache] AlienVault-OTX ({})",
                        self.cache.age_str(Self::FEED_ID)
                    );
                }
                let fd: FeedData = serde_json::from_value(cached).unwrap_or_default();
                *self.data.lock().await = Some(fd.clone());
                return fd;
            }
        }
        if self.verbose {
            eprintln!("  [fetch] AlienVault-OTX (paginated)");
        }
        let mut all = Vec::new();
        for page in 1..=5u32 {
            let url = format!(
                "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page={}",
                page
            );
            match HTTP_CLIENT
                .get(&url)
                .header("X-OTX-API-KEY", &self.api_key)
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => {
                    if let Ok(j) = r.json::<Value>().await {
                        let results = j.get("results").and_then(|v| v.as_array());
                        if let Some(pulses) = results {
                            for pulse in pulses {
                                if let Some(inds) =
                                    pulse.get("indicators").and_then(|v| v.as_array())
                                {
                                    all.extend(inds.iter().cloned());
                                }
                            }
                        }
                        if j.get("next").is_none() {
                            break;
                        }
                    }
                }
                Ok(r) => {
                    eprintln!(
                        "{}",
                        FeedError::HttpOther(r.status().as_u16())
                            .message("AlienVault-OTX")
                            .yellow()
                    );
                    break;
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        FeedError::Network(e.to_string())
                            .message("AlienVault-OTX")
                            .yellow()
                    );
                    break;
                }
            }
        }
        let raw = serde_json::to_string(&all).unwrap_or_default();
        let parsed = otx_parse(&raw);
        if let Ok(v) = serde_json::to_value(&parsed) {
            self.cache.set(Self::FEED_ID, &v);
        }
        *self.data.lock().await = Some(parsed.clone());
        parsed
    }
}

#[async_trait::async_trait]
impl ThreatIntelBackend for OtxCollector {
    fn name(&self) -> &'static str {
        "AlienVault-OTX"
    }
    fn is_remote_api(&self) -> bool {
        false
    }
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        let d = self.load().await;
        if d.ips.contains(ip) {
            vec![ThreatHit {
                source: self.name().into(),
                classification_type: "blacklist".into(),
                classification_taxonomy: "other".into(),
                confidence: 0.75,
                details: json!({ "feed": "AlienVault-OTX" }),
            }]
        } else {
            vec![]
        }
    }
    async fn check_domain(&self, domain: &str) -> Vec<ThreatHit> {
        let d = self.load().await;
        for i in 0..domain.split('.').count() {
            let c = domain.split('.').skip(i).collect::<Vec<_>>().join(".");
            if d.domains.contains(&c) {
                return vec![ThreatHit {
                    source: self.name().into(),
                    classification_type: "blacklist".into(),
                    classification_taxonomy: "other".into(),
                    confidence: 0.72,
                    details: json!({ "feed": "AlienVault-OTX", "matched": c }),
                }];
            }
        }
        vec![]
    }
    async fn check_url(&self, url: &str) -> Vec<ThreatHit> {
        let d = self.load().await;
        if d.urls.contains(url) {
            vec![ThreatHit {
                source: self.name().into(),
                classification_type: "blacklist".into(),
                classification_taxonomy: "other".into(),
                confidence: 0.72,
                details: json!({ "feed": "AlienVault-OTX", "matched": url }),
            }]
        } else {
            vec![]
        }
    }
}

// =============================================================================
// 7. Remote API Backends  (is_remote_api = true → rate limiting applies)
// =============================================================================

struct AbuseIPDBBackend {
    api_key: String,
    min_score: u8,
    cache: Arc<Mutex<HashMap<String, Vec<ThreatHit>>>>,
}
#[async_trait::async_trait]
impl ThreatIntelBackend for AbuseIPDBBackend {
    fn name(&self) -> &'static str {
        "AbuseIPDB"
    }
    fn is_remote_api(&self) -> bool {
        true
    }
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        {
            let g = self.cache.lock().await;
            if let Some(h) = g.get(ip) {
                return h.clone();
            }
        }
        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ip
        );
        let mut hits = Vec::new();
        if let Ok(r) = HTTP_CLIENT
            .get(&url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
        {
            if let Ok(j) = r.json::<Value>().await {
                if let Some(score) = j["data"]["abuseConfidenceScore"].as_u64() {
                    if score as u8 >= self.min_score {
                        hits.push(ThreatHit {
                            source: self.name().into(),
                            classification_type: "blacklist".into(),
                            classification_taxonomy: "other".into(),
                            confidence: score as f64 / 100.0,
                            details: j["data"].clone(),
                        });
                    }
                }
            }
        }
        self.cache.lock().await.insert(ip.to_string(), hits.clone());
        hits
    }
    async fn check_domain(&self, _: &str) -> Vec<ThreatHit> {
        vec![]
    }
    async fn check_url(&self, _: &str) -> Vec<ThreatHit> {
        vec![]
    }
}

struct VirusTotalBackend {
    api_key: String,
    min_detections: u32,
    cache: Arc<Mutex<HashMap<String, Vec<ThreatHit>>>>,
}
impl VirusTotalBackend {
    async fn lookup(&self, endpoint: &str, id: &str) -> Vec<ThreatHit> {
        let key = format!("{}/{}", endpoint, id);
        {
            let g = self.cache.lock().await;
            if let Some(h) = g.get(&key) {
                return h.clone();
            }
        }
        let url = format!("https://www.virustotal.com/api/v3/{}/{}", endpoint, id);
        let mut hits = Vec::new();
        if let Ok(r) = HTTP_CLIENT
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
        {
            if let Ok(j) = r.json::<Value>().await {
                if let Some(attrs) = j.get("data").and_then(|d| d.get("attributes")) {
                    let stats = attrs.get("last_analysis_stats").unwrap_or(&json!(null));
                    let mal = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0);
                    let sus = stats
                        .get("suspicious")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let total = stats
                        .as_object()
                        .map(|o| o.values().map(|v| v.as_u64().unwrap_or(0)).sum::<u64>())
                        .unwrap_or(1);
                    if mal + sus >= self.min_detections as u64 {
                        hits.push(ThreatHit {
                            source:                  self.name().into(),
                            classification_type:     if mal > 0 { "malware" } else { "ids-alert" }.into(),
                            classification_taxonomy: if mal > 0 { "malicious-code" } else { "intrusion-attempts" }.into(),
                            confidence:              (mal + sus) as f64 / total as f64,
                            details: json!({ "malicious": mal, "suspicious": sus,
                                            "total_engines": total,
                                            "reputation": attrs.get("reputation").unwrap_or(&json!(0)) }),
                        });
                    }
                }
            }
        }
        self.cache.lock().await.insert(key, hits.clone());
        hits
    }
}
#[async_trait::async_trait]
impl ThreatIntelBackend for VirusTotalBackend {
    fn name(&self) -> &'static str {
        "VirusTotal"
    }
    fn is_remote_api(&self) -> bool {
        true
    }
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        self.lookup("ip_addresses", ip).await
    }
    async fn check_domain(&self, d: &str) -> Vec<ThreatHit> {
        self.lookup("domains", d).await
    }
    async fn check_url(&self, url: &str) -> Vec<ThreatHit> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        self.lookup("urls", &URL_SAFE_NO_PAD.encode(url.as_bytes()))
            .await
    }
}

struct ShodanBackend {
    api_key: String,
    cache: Arc<Mutex<HashMap<String, Vec<ThreatHit>>>>,
}
#[async_trait::async_trait]
impl ThreatIntelBackend for ShodanBackend {
    fn name(&self) -> &'static str {
        "Shodan"
    }
    fn is_remote_api(&self) -> bool {
        true
    }
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        {
            let g = self.cache.lock().await;
            if let Some(h) = g.get(ip) {
                return h.clone();
            }
        }
        let url = format!(
            "https://api.shodan.io/shodan/host/{}?key={}",
            ip, self.api_key
        );
        let mut hits = Vec::new();
        if let Ok(r) = HTTP_CLIENT.get(&url).send().await {
            if r.status().is_success() {
                if let Ok(j) = r.json::<Value>().await {
                    let tags: HashSet<&str> = j
                        .get("tags")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
                        .unwrap_or_default();
                    let dangerous: Vec<&str> = tags
                        .iter()
                        .filter(|t| {
                            matches!(
                                **t,
                                "malware" | "c2" | "scanner" | "honeypot" | "compromised"
                            )
                        })
                        .cloned()
                        .collect();
                    let ports: Vec<u64> = j
                        .get("ports")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|p| p.as_u64()).collect())
                        .unwrap_or_default();
                    let sus_ports: Vec<u64> = ports
                        .iter()
                        .filter(|p| SUSPICIOUS_PORTS.contains(&(**p as u16)))
                        .cloned()
                        .collect();
                    if !dangerous.is_empty() || !sus_ports.is_empty() {
                        hits.push(ThreatHit {
                            source: self.name().into(),
                            classification_type: "potentially-unwanted-accessible".into(),
                            classification_taxonomy: "vulnerable".into(),
                            confidence: 0.65,
                            details: json!({ "dangerous_tags": dangerous, "open_ports": ports,
                                            "suspicious_ports": sus_ports,
                                            "country": j.get("country_name"),
                                            "org":     j.get("org") }),
                        });
                    }
                }
            }
        }
        self.cache.lock().await.insert(ip.to_string(), hits.clone());
        hits
    }
    async fn check_domain(&self, _: &str) -> Vec<ThreatHit> {
        vec![]
    }
    async fn check_url(&self, _: &str) -> Vec<ThreatHit> {
        vec![]
    }
}

struct IntelMQBackend {
    base_url: String,
    username: String,
    password: String,
    token: Arc<Mutex<Option<String>>>,
    cache: Arc<Mutex<HashMap<String, Vec<ThreatHit>>>>,
}
impl IntelMQBackend {
    async fn login(&self) -> Option<String> {
        let r = HTTP_CLIENT
            .post(format!("{}/v1/api/login/", self.base_url))
            .form(&[("username", &self.username), ("password", &self.password)])
            .send()
            .await
            .ok()?;
        r.json::<Value>()
            .await
            .ok()?
            .get("login_token")?
            .as_str()
            .map(|s| s.to_string())
    }
    async fn lookup(&self, field: &str, value: &str) -> Vec<ThreatHit> {
        let key = format!("{}:{}", field, value);
        {
            let g = self.cache.lock().await;
            if let Some(h) = g.get(&key) {
                return h.clone();
            }
        }
        let token = {
            let mut g = self.token.lock().await;
            if g.is_none() {
                *g = self.login().await;
            }
            g.clone()
        };
        let token = match token {
            Some(t) => t,
            None => return vec![],
        };
        let url = format!("{}/v1/api/events?{}={}", self.base_url, field, value);
        let mut hits = Vec::new();
        if let Ok(r) = HTTP_CLIENT
            .get(&url)
            .header("Authorization", &token)
            .send()
            .await
        {
            if let Ok(events) = r.json::<Vec<Value>>().await {
                for ev in events {
                    let details: serde_json::Map<String, Value> = ev
                        .as_object()
                        .unwrap()
                        .iter()
                        .filter_map(|(k, v)| {
                            if k.starts_with("source.") || k.starts_with("feed.") {
                                Some((k.clone(), v.clone()))
                            } else {
                                None
                            }
                        })
                        .collect();
                    hits.push(ThreatHit {
                        source: self.name().into(),
                        classification_type: ev
                            .get("classification.type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("undetermined")
                            .into(),
                        classification_taxonomy: ev
                            .get("classification.taxonomy")
                            .and_then(|v| v.as_str())
                            .unwrap_or("other")
                            .into(),
                        confidence: 0.75,
                        details: Value::Object(details),
                    });
                }
            }
        }
        self.cache.lock().await.insert(key, hits.clone());
        hits
    }
}
#[async_trait::async_trait]
impl ThreatIntelBackend for IntelMQBackend {
    fn name(&self) -> &'static str {
        "IntelMQ-API"
    }
    fn is_remote_api(&self) -> bool {
        true
    }
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        self.lookup("source.ip", ip).await
    }
    async fn check_domain(&self, d: &str) -> Vec<ThreatHit> {
        self.lookup("source.fqdn", d).await
    }
    async fn check_url(&self, url: &str) -> Vec<ThreatHit> {
        self.lookup("source.url", url).await
    }
}

// Local heuristics
struct LocalHeuristicBackend;
#[async_trait::async_trait]
impl ThreatIntelBackend for LocalHeuristicBackend {
    fn name(&self) -> &'static str {
        "LocalHeuristic"
    }
    fn is_remote_api(&self) -> bool {
        false
    }
    async fn check_domain(&self, domain: &str) -> Vec<ThreatHit> {
        lazy_static::lazy_static! {
            static ref PATTERNS: Vec<(Regex, &'static str, f64)> = vec![
                (Regex::new(r"^[a-z0-9]{16,}\.[a-z]{2,4}$").unwrap(),             "Long random label — possible DGA", 0.55),
                (Regex::new(r"^[a-z0-9]{8,}\.(xyz|top|tk|ml|ga|cf|gq|pw)$").unwrap(), "DGA-like + cheap TLD",         0.65),
                (Regex::new(r"^[a-z]{3,6}[0-9]{4,}\.[a-z]{2,4}$").unwrap(),       "Alphanumeric mix — possible DGA", 0.50),
            ];
        }
        for (re, reason, conf) in PATTERNS.iter() {
            if re.is_match(domain) {
                return vec![ThreatHit {
                    source: self.name().into(),
                    classification_type: "dga-domain".into(),
                    classification_taxonomy: "malicious-code".into(),
                    confidence: *conf,
                    details: json!({ "reason": reason }),
                }];
            }
        }
        vec![]
    }
    async fn check_ip(&self, _: &str) -> Vec<ThreatHit> {
        vec![]
    }
    async fn check_url(&self, _: &str) -> Vec<ThreatHit> {
        vec![]
    }
}

// =============================================================================
// 8. Analysis Engine
// =============================================================================

struct Analyser {
    backends: Vec<Arc<dyn ThreatIntelBackend>>,
    rate_limit_ms: u64,
    verbose: bool,
    quiet: bool,
}

impl Analyser {
    async fn analyse(&self, observables: &[Observable]) -> Vec<ThreatMatch> {
        let total = (observables.len() * self.backends.len()) as u64;
        let mut all_matches = Vec::new();
        let mut total_hits: usize = 0;

        let pb = if !self.quiet {
            let pb = ProgressBar::new(total);
            pb.set_style(ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.green/black} {pos:>5}/{len} checks  hits:{msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ "));
            pb.set_message("0");
            Some(pb)
        } else {
            None
        };

        for obs in observables {
            for backend in &self.backends {
                let hits = match obs.kind.as_str() {
                    "ip" => backend.check_ip(&obs.value).await,
                    "domain" => backend.check_domain(&obs.value).await,
                    "url" => backend.check_url(&obs.value).await,
                    _ => vec![],
                };

                if self.verbose {
                    let indicator = if hits.is_empty() {
                        "·".dimmed().to_string()
                    } else {
                        format!("{}", format!("HIT×{}", hits.len()).red().bold())
                    };
                    let msg = format!(
                        "  [{:>6}] {:>22}  {}  {}",
                        obs.kind,
                        truncate(backend.name(), 22),
                        indicator,
                        truncate(&obs.value, 38)
                    );
                    if let Some(pb) = &pb {
                        pb.println(msg);
                    } else {
                        eprintln!("{}", msg);
                    }
                }

                total_hits += hits.len();
                if let Some(pb) = &pb {
                    pb.set_message(total_hits.to_string());
                    pb.inc(1);
                }

                for h in hits {
                    all_matches.push(ThreatMatch {
                        observable: obs.clone(),
                        ti_source: h.source,
                        classification_type: h.classification_type,
                        classification_taxonomy: h.classification_taxonomy,
                        confidence: h.confidence,
                        details: h.details,
                    });
                }

                // Rate limit ONLY for remote API backends
                if backend.is_remote_api() && self.rate_limit_ms > 0 {
                    sleep(Duration::from_millis(self.rate_limit_ms)).await;
                }
            }
        }

        if let Some(pb) = pb {
            pb.finish_with_message(total_hits.to_string());
        }
        all_matches
    }
}

// =============================================================================
// 9. Per-file summary
// =============================================================================

fn print_file_summary(path: &Path, obs: &[Observable], matches: &[ThreatMatch], quiet: bool) {
    if quiet {
        return;
    }
    let fname = path.file_name().unwrap_or_default().to_string_lossy();
    let n_ip = obs.iter().filter(|o| o.kind == "ip").count();
    let n_dom = obs.iter().filter(|o| o.kind == "domain").count();
    let n_url = obs.iter().filter(|o| o.kind == "url").count();
    let n_hits = matches.len();
    let hit_obs = matches
        .iter()
        .map(|m| &m.observable.value)
        .collect::<HashSet<_>>()
        .len();

    let status = if n_hits == 0 {
        "clean".green().bold().to_string()
    } else {
        format!("{} match(es) on {} observable(s)", n_hits, hit_obs)
            .red()
            .bold()
            .to_string()
    };

    println!(
        "  {}  {}  [{} ip  {} domain  {} url]  →  {}",
        "▶".cyan(),
        fname.bold(),
        n_ip,
        n_dom,
        n_url,
        status
    );
}

// =============================================================================
// 10. Final consolidated report
// =============================================================================

fn print_final_report(
    all_obs: &[Observable],
    all_matches: &[ThreatMatch],
    backends: &[Arc<dyn ThreatIntelBackend>],
    n_files: usize,
) {
    let sep = "═".repeat(100);
    println!("\n{}", sep.cyan());
    println!(
        "{}",
        format!(
            "  {} v{}  —  Consolidated Report  ({} file(s))",
            TOOL_NAME, VERSION, n_files
        )
        .cyan()
        .bold()
    );
    println!("{}", sep.cyan());

    let n_ip = all_obs.iter().filter(|o| o.kind == "ip").count();
    let n_dom = all_obs.iter().filter(|o| o.kind == "domain").count();
    let n_url = all_obs.iter().filter(|o| o.kind == "url").count();
    let hit_obs_vals: HashSet<&str> = all_matches
        .iter()
        .map(|m| m.observable.value.as_str())
        .collect();

    println!(
        "  Observables : {} total  ({} {}, {} {}, {} {})",
        all_obs.len(),
        n_ip,
        " IP  ".on_blue().white(),
        n_dom,
        " DOM ".on_magenta().white(),
        n_url,
        " URL ".on_cyan().black(),
    );
    println!(
        "  Backends    : {}",
        backends
            .iter()
            .map(|b| b.name())
            .collect::<Vec<_>>()
            .join("  ·  ")
    );
    if all_matches.is_empty() {
        println!(
            "\n  {}  No threats detected across all files.\n",
            "✅".green()
        );
        return;
    }

    let high = all_matches.iter().filter(|m| m.confidence >= 0.75).count();
    let med = all_matches
        .iter()
        .filter(|m| m.confidence >= 0.45 && m.confidence < 0.75)
        .count();
    let low = all_matches.iter().filter(|m| m.confidence < 0.45).count();
    println!(
        "  Threats     : {} match(es) on {} unique observable(s)  [ {} HIGH  {} MED  {} LOW ]",
        all_matches.len().to_string().red().bold(),
        hit_obs_vals.len().to_string().red(),
        high.to_string().red().bold(),
        med.to_string().yellow().bold(),
        low.to_string().cyan().bold(),
    );

    // ── Threat matches table ──────────────────────────────────────────────────
    println!("\n{}", "─── Threat Matches ─────────────────────────────────────────────────────────────────────────────────".dimmed());
    println!(
        "  {:<6}  {:<5}  {:<32}  {:<16}  {:<22}  {:<22}  {:>4}  {}",
        "SEV", "TYPE", "OBSERVABLE", "TI SOURCE", "CLASS.TYPE", "TAXONOMY", "CONF", "KEY DETAIL"
    );
    println!("{}", "─".repeat(140).dimmed());

    let mut sorted = all_matches.to_vec();
    sorted.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

    for m in sorted.iter().take(100) {
        let pct = format!("{:>3}%", (m.confidence * 100.0) as usize);
        let conf_col = if m.confidence >= 0.75 {
            pct.red().bold()
        } else if m.confidence >= 0.45 {
            pct.yellow().bold()
        } else {
            pct.cyan()
        };
        let detail: &str = m
            .details
            .get("reason")
            .or_else(|| m.details.get("matched"))
            .or_else(|| m.details.get("matched_cidr"))
            .or_else(|| m.details.get("isp"))
            .or_else(|| m.details.get("org"))
            .or_else(|| m.details.get("countryCode"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!(
            "  {}  {}  {:<32}  {:<16}  {:<22}  {:<22}  {}  {}",
            severity_badge(m.confidence),
            kind_badge(&m.observable.kind),
            truncate(&m.observable.value, 31),
            truncate(&m.ti_source, 15),
            truncate(&m.classification_type, 21),
            truncate(&m.classification_taxonomy, 21),
            conf_col,
            truncate(detail, 40),
        );
    }
    if sorted.len() > 100 {
        println!(
            "  {}",
            format!(
                "  … {} more matches not shown — use --output-json for full results",
                sorted.len() - 100
            )
            .dimmed()
        );
    }

    // ── Hit observables detail ────────────────────────────────────────────────
    println!("\n{}", "─── Flagged Observables ─────────────────────────────────────────────────────────────────────────────".dimmed());
    println!(
        "  {:<5}  {:<38}  {:<14}  {:>5}  {:<16}  {}",
        "TYPE", "VALUE", "CONTEXT", "COUNT", "FILE", "SOURCES"
    );
    println!("{}", "─".repeat(120).dimmed());

    let mut hit_obs_list: Vec<&Observable> = all_obs
        .iter()
        .filter(|o| hit_obs_vals.contains(o.value.as_str()))
        .collect();
    hit_obs_list.sort_by(|a, b| b.count.cmp(&a.count));

    for obs in hit_obs_list.iter().take(50) {
        let sources: Vec<&str> = all_matches
            .iter()
            .filter(|m| m.observable.value == obs.value)
            .map(|m| m.ti_source.as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        println!(
            "  {}  {:<38}  {:<14}  {:>5}  {:<16}  {}",
            kind_badge(&obs.kind),
            truncate(&obs.value, 37),
            truncate(&obs.context, 13),
            obs.count,
            truncate(
                Path::new(&obs.source_file)
                    .file_name()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or(""),
                15
            ),
            sources.join(", "),
        );
    }

    // ── Feed status ────────────────────────────────────────────────────────────
    println!("\n{}", "─── Feed Status ─────────────────────────────────────────────────────────────────────────────────────".dimmed());
    println!("  {:<22}  {:<8}  {}", "FEED", "REMOTE?", "STATUS");
    println!("{}", "─".repeat(60).dimmed());
    for b in backends.iter() {
        let remote = if b.is_remote_api() {
            "API   "
        } else {
            "local "
        };
        println!("  {:<22}  {}  {}", b.name(), remote, "active".green());
    }
    println!();
}

// =============================================================================
// 11. Export
// =============================================================================

fn export_json(matches: &[ThreatMatch], obs: &[Observable], path: &str) -> Result<()> {
    let out = json!({
        "tool":         TOOL_NAME,
        "version":      VERSION,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "summary": {
            "total_observables": obs.len(),
            "total_matches":     matches.len(),
            "unique_hits":       matches.iter().map(|m| &m.observable.value)
                                    .collect::<HashSet<_>>().len(),
        },
        "observables":    obs,
        "threat_matches": matches,
    });
    fs::write(path, serde_json::to_string_pretty(&out)?)?;
    Ok(())
}

fn export_csv(
    matches: &[ThreatMatch],
    obs_index: &HashMap<String, &Observable>,
    path: &str,
) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    // Header — richer than v2.0
    wtr.write_record(&[
        // Observable columns
        "asset_type", // ip | domain | url
        "asset_value",
        "asset_context", // dns-query, http-host, source, destination…
        "asset_count",   // how many packets contained this observable
        "source_file",
        // TI hit columns
        "ti_source",
        "classification_type",
        "classification_taxonomy",
        "severity",       // HIGH | MED | LOW  (derived from confidence)
        "confidence_pct", // 0–100 integer
        // Expanded detail columns (stable across most feeds)
        "detail_matched",     // exact matched value (CIDR, URL prefix, domain…)
        "detail_reason",      // heuristic reason text
        "detail_abuse_score", // AbuseIPDB score
        "detail_isp",         // AbuseIPDB ISP
        "detail_country",     // AbuseIPDB / Shodan country
        "detail_malicious_engines", // VirusTotal
        "detail_suspicious_engines", // VirusTotal
        "detail_total_engines", // VirusTotal
        "detail_dangerous_tags", // Shodan
        "detail_suspicious_ports", // Shodan
        // Raw JSON for any remaining detail fields
        "details_json",
    ])?;

    let str_val = |v: &Value| -> String {
        match v {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        }
    };

    for m in matches {
        let obs_key = format!("{}:{}", m.observable.kind, m.observable.value);
        let obs = obs_index.get(&obs_key);

        wtr.write_record(&[
            &m.observable.kind,
            &m.observable.value,
            obs.map(|o| o.context.as_str()).unwrap_or(""),
            &obs.map(|o| o.count.to_string()).unwrap_or_default(),
            &m.observable.source_file,
            &m.ti_source,
            &m.classification_type,
            &m.classification_taxonomy,
            m.severity(),
            &format!("{}", (m.confidence * 100.0) as u32),
            // Expanded details
            &str_val(
                m.details
                    .get("matched")
                    .unwrap_or(m.details.get("matched_cidr").unwrap_or(&Value::Null)),
            ),
            &str_val(m.details.get("reason").unwrap_or(&Value::Null)),
            &str_val(
                &m.details
                    .get("abuseConfidenceScore")
                    .or_else(|| m.details.get("abuse_score"))
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            &str_val(m.details.get("isp").unwrap_or(&Value::Null)),
            &str_val(
                m.details
                    .get("countryCode")
                    .or_else(|| m.details.get("country"))
                    .unwrap_or(&Value::Null),
            ),
            &str_val(m.details.get("malicious").unwrap_or(&Value::Null)),
            &str_val(m.details.get("suspicious").unwrap_or(&Value::Null)),
            &str_val(m.details.get("total_engines").unwrap_or(&Value::Null)),
            &m.details
                .get("dangerous_tags")
                .map(|v| v.to_string())
                .unwrap_or_default(),
            &m.details
                .get("suspicious_ports")
                .map(|v| v.to_string())
                .unwrap_or_default(),
            &serde_json::to_string(&m.details).unwrap_or_default(),
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

// =============================================================================
// 12. CLI
// =============================================================================

fn build_cli() -> Command {
    Command::new(TOOL_NAME)
        .version(VERSION)
        .about("Analyse PCAP files against IntelMQ-compatible threat intelligence feeds")
        .arg(
            Arg::new("pcap_files")
                .required(true)
                .num_args(1..)
                .help("PCAP/CAP files to analyse"),
        )
        .arg(
            Arg::new("workers")
                .long("workers")
                .default_value("4")
                .help("Parallel extraction workers"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(ArgAction::SetTrue)
                .help("Suppress all output except errors"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Show per-check detail"),
        )
        .arg(
            Arg::new("refresh-feeds")
                .long("refresh-feeds")
                .action(ArgAction::SetTrue)
                .help("Force re-download all feeds"),
        )
        .arg(
            Arg::new("cache-dir")
                .long("cache-dir")
                .default_value(DEFAULT_CACHE_DIR),
        )
        .arg(
            Arg::new("include-private")
                .long("include-private")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("kinds")
                .long("kinds")
                .num_args(1..)
                .default_value("ip domain url"),
        )
        .arg(
            Arg::new("output-json")
                .long("output-json")
                .value_name("FILE"),
        )
        .arg(Arg::new("output-csv").long("output-csv").value_name("FILE"))
        .arg(
            Arg::new("rate-limit")
                .long("rate-limit")
                .default_value("0.2")
                .help("Seconds between remote API calls"),
        )
        // Feed disable flags
        .arg(
            Arg::new("no-urlhaus")
                .long("no-urlhaus")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-feodo")
                .long("no-feodo")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-phishtank")
                .long("no-phishtank")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-bambenek")
                .long("no-bambenek")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-blocklist-de")
                .long("no-blocklist-de")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-emerging-threats")
                .long("no-emerging-threats")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-heuristics")
                .long("no-heuristics")
                .action(ArgAction::SetTrue),
        )
        // API keys
        .arg(
            Arg::new("abuseipdb-key")
                .long("abuseipdb-key")
                .env("ABUSEIPDB_KEY"),
        )
        .arg(
            Arg::new("abuseipdb-min-score")
                .long("abuseipdb-min-score")
                .default_value("25"),
        )
        .arg(
            Arg::new("virustotal-key")
                .long("virustotal-key")
                .env("VIRUSTOTAL_KEY"),
        )
        .arg(
            Arg::new("virustotal-min-detections")
                .long("virustotal-min-detections")
                .default_value("2"),
        )
        .arg(Arg::new("shodan-key").long("shodan-key").env("SHODAN_KEY"))
        .arg(Arg::new("otx-key").long("otx-key").env("OTX_KEY"))
        .arg(
            Arg::new("phishtank-key")
                .long("phishtank-key")
                .env("PHISHTANK_KEY"),
        )
        .arg(Arg::new("intelmq-url").long("intelmq-url"))
        .arg(Arg::new("intelmq-user").long("intelmq-user"))
        .arg(Arg::new("intelmq-pass").long("intelmq-pass"))
}

// =============================================================================
// 13. Main
// =============================================================================

async fn run() -> Result<()> {
    let args = build_cli().get_matches();
    let quiet = args.get_flag("quiet");
    let verbose = args.get_flag("verbose") && !quiet;
    let refresh_feeds = args.get_flag("refresh-feeds");
    let include_priv = args.get_flag("include-private");
    let workers: usize = args
        .get_one::<String>("workers")
        .unwrap()
        .parse()
        .unwrap_or(4);
    let rate_ms: u64 = (args
        .get_one::<String>("rate-limit")
        .unwrap()
        .parse::<f64>()
        .unwrap_or(0.2)
        * 1000.0) as u64;
    let cache_dir = PathBuf::from(args.get_one::<String>("cache-dir").unwrap());
    let kinds: HashSet<String> = args
        .get_one::<String>("kinds")
        .unwrap()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let pcap_files: Vec<PathBuf> = args
        .get_many::<String>("pcap_files")
        .unwrap()
        .map(PathBuf::from)
        .collect();

    let cache = Arc::new(FeedCache::new(cache_dir));
    let mut backends: Vec<Arc<dyn ThreatIntelBackend>> = Vec::new();

    macro_rules! feed {
        ($name:expr, $id:expr, $url:expr, $ttl:expr,
         $it:expr,$ix:expr,$ic:expr,
         $dt:expr,$dx:expr,$dc:expr,
         $ut:expr,$ux:expr,$uc:expr,
         $parser:expr) => {
            Arc::new(FeedCollector::new(
                $name,
                $id,
                $url.to_string(),
                $ttl,
                cache.clone(),
                refresh_feeds,
                verbose,
                $it,
                $ix,
                $ic,
                $dt,
                $dx,
                $dc,
                $ut,
                $ux,
                $uc,
                $parser,
            ))
        };
    }

    if !args.get_flag("no-urlhaus") {
        backends.push(feed!(
            "URLhaus",
            "urlhaus",
            "https://urlhaus.abuse.ch/downloads/csv/",
            3600,
            "malware-distribution",
            "malicious-code",
            0.90,
            "malware-distribution",
            "malicious-code",
            0.90,
            "malware-distribution",
            "malicious-code",
            0.90,
            urlhaus_parse
        ));
    }
    if !args.get_flag("no-feodo") {
        backends.push(feed!(
            "FeodoTracker",
            "feodo_tracker",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            3600,
            "c2-server",
            "malicious-code",
            0.95,
            "",
            "",
            0.0,
            "",
            "",
            0.0,
            feodo_parse
        ));
    }
    if !args.get_flag("no-phishtank") {
        let key = args
            .get_one::<String>("phishtank-key")
            .cloned()
            .unwrap_or_default();
        let url = if key.is_empty() {
            "https://data.phishtank.com/data/online-valid.csv".to_string()
        } else {
            format!("https://data.phishtank.com/data/{}/online-valid.csv", key)
        };
        backends.push(feed!(
            "PhishTank",
            "phishtank",
            url,
            3600,
            "",
            "",
            0.0,
            "phishing",
            "fraud",
            0.92,
            "phishing",
            "fraud",
            0.92,
            phishtank_parse
        ));
    }
    if !args.get_flag("no-bambenek") {
        backends.push(feed!(
            "Bambenek",
            "bambenek_c2",
            "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt",
            3600,
            "",
            "",
            0.0,
            "c2-server",
            "malicious-code",
            0.88,
            "",
            "",
            0.0,
            bambenek_parse
        ));
    }
    if !args.get_flag("no-blocklist-de") {
        backends.push(feed!(
            "Blocklist.de",
            "blocklist_de",
            "https://lists.blocklist.de/lists/all.txt",
            43200,
            "brute-force",
            "intrusion-attempts",
            0.80,
            "",
            "",
            0.0,
            "",
            "",
            0.0,
            blocklist_de_parse
        ));
    }
    if !args.get_flag("no-emerging-threats") {
        backends.push(feed!(
            "EmergingThreats",
            "emerging_threats",
            "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
            86400,
            "infected-system",
            "malicious-code",
            0.82,
            "",
            "",
            0.0,
            "",
            "",
            0.0,
            emerging_threats_parse
        ));
    }
    if let Some(key) = args.get_one::<String>("otx-key").filter(|k| !k.is_empty()) {
        backends.push(Arc::new(OtxCollector {
            api_key: key.clone(),
            cache: cache.clone(),
            force_refresh: refresh_feeds,
            verbose,
            data: Arc::new(Mutex::new(None)),
        }));
    }
    if let Some(key) = args
        .get_one::<String>("abuseipdb-key")
        .filter(|k| !k.is_empty())
    {
        let min: u8 = args
            .get_one::<String>("abuseipdb-min-score")
            .unwrap()
            .parse()
            .unwrap_or(25);
        backends.push(Arc::new(AbuseIPDBBackend {
            api_key: key.clone(),
            min_score: min,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }));
    }
    if let Some(key) = args
        .get_one::<String>("virustotal-key")
        .filter(|k| !k.is_empty())
    {
        let min: u32 = args
            .get_one::<String>("virustotal-min-detections")
            .unwrap()
            .parse()
            .unwrap_or(2);
        backends.push(Arc::new(VirusTotalBackend {
            api_key: key.clone(),
            min_detections: min,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }));
    }
    if let Some(key) = args
        .get_one::<String>("shodan-key")
        .filter(|k| !k.is_empty())
    {
        backends.push(Arc::new(ShodanBackend {
            api_key: key.clone(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }));
    }
    if let (Some(url), Some(user), Some(pass)) = (
        args.get_one::<String>("intelmq-url")
            .filter(|s| !s.is_empty()),
        args.get_one::<String>("intelmq-user")
            .filter(|s| !s.is_empty()),
        args.get_one::<String>("intelmq-pass"),
    ) {
        backends.push(Arc::new(IntelMQBackend {
            base_url: url.clone(),
            username: user.clone(),
            password: pass.clone(),
            token: Arc::new(Mutex::new(None)),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }));
    }
    if !args.get_flag("no-heuristics") {
        backends.push(Arc::new(LocalHeuristicBackend));
    }

    if !quiet {
        println!(
            "{} v{}  (Rust · {} backends)",
            TOOL_NAME,
            VERSION,
            backends.len()
        );
    }

    // Extract observables in parallel using rayon
    if !quiet {
        println!(
            "\nExtracting observables from {} file(s) with {} workers…",
            pcap_files.len(),
            workers
        );
    }

    let all_obs: Vec<Observable> = pcap_files
        .par_iter()
        .flat_map(
            |p| match extract_observables_from_pcap(p, include_priv, &kinds) {
                Ok(obs) => obs,
                Err(e) => {
                    eprintln!("{} {}: {}", "ERROR".red().bold(), p.display(), e);
                    vec![]
                }
            },
        )
        .collect();

    // Deduplicate
    let mut dedup: HashMap<String, Observable> = HashMap::new();
    for o in all_obs {
        dedup
            .entry(format!("{}:{}", o.kind, o.value))
            .and_modify(|e| e.count += o.count)
            .or_insert(o);
    }
    let unique_obs: Vec<Observable> = dedup.into_values().collect();

    if unique_obs.is_empty() {
        if !quiet {
            println!("No analysable observables found.");
        }
        return Ok(());
    }
    if !quiet {
        let n_ip = unique_obs.iter().filter(|o| o.kind == "ip").count();
        let n_dom = unique_obs.iter().filter(|o| o.kind == "domain").count();
        let n_url = unique_obs.iter().filter(|o| o.kind == "url").count();
        println!(
            "Unique observables: {}  (IPs: {}  domains: {}  URLs: {})",
            unique_obs.len(),
            n_ip,
            n_dom,
            n_url
        );
    }

    let analyser = Analyser {
        backends: backends.clone(),
        rate_limit_ms: rate_ms,
        verbose,
        quiet,
    };
    let matches = analyser.analyse(&unique_obs).await;

    // Per-file summaries
    if !quiet {
        println!();
        for p in &pcap_files {
            let file_obs: Vec<&Observable> = unique_obs
                .iter()
                .filter(|o| o.source_file == p.display().to_string())
                .collect();
            let file_matches: Vec<&ThreatMatch> = matches
                .iter()
                .filter(|m| m.observable.source_file == p.display().to_string())
                .collect();
            let obs_owned: Vec<Observable> = file_obs.iter().map(|o| (*o).clone()).collect();
            let mat_owned: Vec<ThreatMatch> = file_matches.iter().map(|m| (*m).clone()).collect();
            print_file_summary(p, &obs_owned, &mat_owned, quiet);
        }
    }

    if !quiet {
        print_final_report(&unique_obs, &matches, &backends, pcap_files.len());
    }

    if let Some(path) = args.get_one::<String>("output-json") {
        export_json(&matches, &unique_obs, path)?;
        if !quiet {
            println!("  JSON  → {}", path);
        }
    }
    if let Some(path) = args.get_one::<String>("output-csv") {
        // Build index for enriching CSV rows with observable metadata
        let obs_index: HashMap<String, &Observable> = unique_obs
            .iter()
            .map(|o| (format!("{}:{}", o.kind, o.value), o))
            .collect();
        export_csv(&matches, &obs_index, path)?;
        if !quiet {
            println!("  CSV   → {}", path);
        }
    }

    Ok(())
}
