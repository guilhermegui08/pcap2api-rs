// =============================================================================
// pcap2api-rs - Full Rust implementation (all features, compiles, Send-safe)
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
const VERSION: &str = "2.0.0";
const TOOL_NAME: &str = "pcap2api-rs";
const DEFAULT_CACHE_DIR: &str = ".cache/pcap2api-rs";

lazy_static::lazy_static! {
    static ref PRIVATE_NETS: Vec<ipnet::IpNet> = {
        let strs = vec![
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
            "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
        ];
        strs.iter().map(|s| s.parse().unwrap()).collect()
    };
    static ref SERVICES: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        m.insert(21, "ftp"); m.insert(22, "ssh"); m.insert(23, "telnet");
        m.insert(25, "smtp"); m.insert(53, "dns"); m.insert(80, "http");
        m.insert(110, "pop3"); m.insert(143, "imap"); m.insert(443, "https");
        m.insert(445, "smb"); m.insert(3306, "mysql"); m.insert(3389, "rdp");
        m.insert(5432, "postgresql"); m.insert(6379, "redis"); m.insert(8080, "http-alt");
        m.insert(8443, "https-alt"); m.insert(27017, "mongodb"); m.insert(6667, "irc");
        m.insert(4444, "metasploit"); m.insert(1433, "mssql"); m.insert(5900, "vnc");
        m
    };
    static ref SUSPICIOUS_PORTS: HashSet<u16> = {
        let mut s = HashSet::new();
        s.insert(4444); s.insert(1337); s.insert(31337); s.insert(12345);
        s.insert(54321); s.insert(6666); s.insert(6667); s.insert(6668);
        s.insert(1080); s.insert(9050); s.insert(9051);
        s
    };
    static ref HTTP_CLIENT: reqwest::Client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
}

// =============================================================================
// 1. Data Models
// =============================================================================
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Observable {
    pub kind: String,
    pub value: String,
    pub context: String,
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

// =============================================================================
// 2. Utilities
// =============================================================================
fn is_private_ip(addr: &str) -> bool {
    if let Ok(ip) = addr.parse::<IpAddr>() {
        PRIVATE_NETS.iter().any(|net| net.contains(&ip))
    } else {
        false
    }
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
        let host_re = Regex::new(r"Host:\s*([^\r\n]+)").unwrap();
        let req_re = Regex::new(r"(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)").unwrap();
        if let (Some(host_cap), Some(req_cap)) = (host_re.captures(text), req_re.captures(text)) {
            let host = host_cap[1].trim();
            let path = req_cap[1].trim();
            urls.push(format!("http://{}{}", host, path));
        }
        let url_re = Regex::new(r#"https?://[^\s"'<>]+"#).unwrap();
        for cap in url_re.captures_iter(text) {
            urls.push(cap[0].to_string());
        }
    }
    urls
}

// =============================================================================
// 3. Feed Cache (disk with TTL)
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

    fn get(&self, feed_id: &str, ttl_secs: u64) -> Option<Value> {
        let path = self.path(feed_id);
        if !path.exists() {
            return None;
        }
        let data: CacheEntry = serde_json::from_str(&fs::read_to_string(path).ok()?).ok()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now - data.ts < ttl_secs {
            Some(data.payload)
        } else {
            None
        }
    }

    fn set(&self, feed_id: &str, payload: &Value) {
        let path = self.path(feed_id);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let entry = CacheEntry {
            ts: now,
            payload: payload.clone(),
        };
        let _ = fs::write(path, serde_json::to_string_pretty(&entry).unwrap());
    }

    fn age_str(&self, feed_id: &str) -> String {
        let path = self.path(feed_id);
        if !path.exists() {
            return "no cache".to_string();
        }
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(entry) = serde_json::from_str::<CacheEntry>(&data) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let age = now - entry.ts;
                if age < 120 {
                    return format!("{}s ago", age);
                }
                if age < 7200 {
                    return format!("{}m ago", age / 60);
                }
                return format!("{}h ago", age / 3600);
            }
        }
        "unknown".to_string()
    }
}

// =============================================================================
// 4. PCAP Extraction (streaming, parallel)
// =============================================================================
use pcap::Capture;

fn extract_observables_from_pcap(
    path: &Path,
    include_private: bool,
    kinds: &HashSet<String>,
) -> Result<Vec<Observable>> {
    let mut cap =
        Capture::from_file(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut obs_map: HashMap<String, Observable> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        process_packet(&packet, path, &mut obs_map);
    }

    let mut list: Vec<Observable> = obs_map.into_values().collect();
    list.retain(|o| kinds.contains(&o.kind));
    if !include_private {
        list.retain(|o| o.kind != "ip" || !is_private_ip(&o.value));
    }
    Ok(list)
}

fn process_packet(packet: &pcap::Packet, src_file: &Path, map: &mut HashMap<String, Observable>) {
    if packet.header.caplen < 14 {
        return;
    }
    let eth = &packet.data[..];
    let eth_type = u16::from_be_bytes([eth[12], eth[13]]);
    if eth_type != 0x0800 {
        return; // only IPv4 for simplicity (IPv6 can be added)
    }
    let ip_offset = 14;
    if eth.len() < ip_offset + 20 {
        return;
    }
    let ip = &eth[ip_offset..];
    let src_ip = std::net::Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = std::net::Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let proto = ip[9];
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    let transport_offset = ip_offset + ihl;

    // IP addresses
    add_obs(map, "ip", &src_ip.to_string(), "source", src_file);
    add_obs(map, "ip", &dst_ip.to_string(), "destination", src_file);

    if eth.len() < transport_offset + 4 {
        return;
    }
    let transport = &eth[transport_offset..];
    if proto == 6 && transport.len() >= 20 {
        // TCP
        let dport = u16::from_be_bytes([transport[2], transport[3]]);
        add_obs(map, "port", &dport.to_string(), "tcp", src_file);
        let tcp_hdr_len = ((transport[12] >> 4) & 0x0F) as usize * 4;
        let payload_start = transport_offset + tcp_hdr_len;
        if payload_start < eth.len() {
            let payload = &eth[payload_start..];
            process_http_payload(payload, map, src_file);
        }
    } else if proto == 17 && transport.len() >= 8 {
        // UDP
        let dport = u16::from_be_bytes([transport[2], transport[3]]);
        add_obs(map, "port", &dport.to_string(), "udp", src_file);
        if dport == 53 {
            let payload = &transport[8..];
            if let Ok(parsed) = dns_parser::Packet::parse(payload) {
                for q in parsed.questions {
                    let name = q.qname.to_string();
                    if is_valid_domain(&name) {
                        add_obs(map, "domain", &name, "dns-query", src_file);
                    }
                }
            }
        }
    }
}

fn add_obs(
    map: &mut HashMap<String, Observable>,
    kind: &str,
    value: &str,
    context: &str,
    src_file: &Path,
) {
    let key = format!("{}:{}", kind, value);
    if let Some(entry) = map.get_mut(&key) {
        entry.count += 1;
    } else {
        map.insert(
            key,
            Observable {
                kind: kind.to_string(),
                value: value.to_string(),
                context: context.to_string(),
                source_file: src_file.display().to_string(),
                count: 1,
            },
        );
    }
}

fn process_http_payload(payload: &[u8], map: &mut HashMap<String, Observable>, src_file: &Path) {
    for url in extract_urls_from_payload(payload) {
        add_obs(map, "url", &url, "http", src_file);
        if let Ok(parsed) = Url::parse(&url) {
            if let Some(host) = parsed.host_str() {
                if is_valid_domain(host) {
                    add_obs(map, "domain", host, "http-host", src_file);
                }
            }
        }
    }
}

// =============================================================================
// 5. Threat Intelligence Backends (trait)
// =============================================================================
#[async_trait::async_trait]
trait ThreatIntelBackend: Send + Sync {
    fn name(&self) -> &'static str;
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
// 5a. Local Feed Collectors (IntelMQ pipeline)
// =============================================================================
struct FeedCollector {
    name: &'static str,
    feed_id: &'static str,
    feed_url: String,
    ttl: u64,
    cache: Arc<FeedCache>,
    force_refresh: bool,
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

#[derive(Clone, Default, Serialize, Deserialize)]
struct FeedData {
    ips: HashSet<String>,
    domains: HashSet<String>,
    urls: HashSet<String>,
}

impl FeedCollector {
    fn new<F>(
        name: &'static str,
        feed_id: &'static str,
        feed_url: String,
        ttl: u64,
        cache: Arc<FeedCache>,
        force_refresh: bool,
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
            let guard = self.data.lock().await;
            if let Some(ref d) = *guard {
                return d.clone();
            }
        }
        if !self.force_refresh {
            if let Some(cached) = self.cache.get(self.feed_id, self.ttl) {
                let data: FeedData = serde_json::from_value(cached).unwrap_or_default();
                *self.data.lock().await = Some(data.clone());
                return data;
            }
        }
        let resp = HTTP_CLIENT
            .get(&self.feed_url)
            .header("User-Agent", format!("{}/{}", TOOL_NAME, VERSION))
            .send()
            .await;
        let raw = match resp {
            Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
            Ok(r) => {
                eprintln!(
                    "[{}] feed '{}' HTTP {} from {}",
                    "WARN".yellow(),
                    self.name,
                    r.status(),
                    self.feed_url
                );
                // Fall back to stale cache if available
                if let Some(stale) = self.cache.get(self.feed_id, u64::MAX) {
                    eprintln!(
                        "[{}] using stale cache for '{}' ({})",
                        "WARN".yellow(),
                        self.name,
                        self.cache.age_str(self.feed_id)
                    );
                    let data: FeedData = serde_json::from_value(stale).unwrap_or_default();
                    *self.data.lock().await = Some(data.clone());
                    return data;
                }
                String::new()
            }
            Err(e) => {
                eprintln!(
                    "[{}] feed '{}' network error: {}",
                    "WARN".yellow(),
                    self.name,
                    e
                );
                if let Some(stale) = self.cache.get(self.feed_id, u64::MAX) {
                    eprintln!(
                        "[{}] using stale cache for '{}' ({})",
                        "WARN".yellow(),
                        self.name,
                        self.cache.age_str(self.feed_id)
                    );
                    let data: FeedData = serde_json::from_value(stale).unwrap_or_default();
                    *self.data.lock().await = Some(data.clone());
                    return data;
                }
                String::new()
            }
        };
        let parsed = (self.parse_fn)(&raw);
        self.cache
            .set(self.feed_id, &serde_json::to_value(&parsed).unwrap());
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

    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        if self.ip_type.is_empty() {
            return vec![];
        }
        let data = self.load().await;
        // Exact match
        if data.ips.contains(ip) {
            return vec![self.hit(
                self.ip_type,
                self.ip_tax,
                self.ip_conf,
                json!({ "feed": self.name, "matched": ip }),
            )];
        }
        // CIDR containment match (for feeds that store network ranges)
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
        for feed_url in &data.urls {
            if url == feed_url || url.starts_with(feed_url.as_str()) {
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

// --- Concrete feed parsers ---------------------------------------------------
fn urlhaus_parse(raw: &str) -> FeedData {
    // URLhaus CSV format (abuse.ch):
    //   # comment lines at top, then header, then:
    //   id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    let mut data = FeedData::default();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Simple CSV split honouring one level of double-quotes
        let fields: Vec<&str> = split_csv_line(line);
        // url is field index 2 (0-indexed)
        if fields.len() < 3 {
            continue;
        }
        let url = fields[2].trim_matches('"').trim();
        if url.eq_ignore_ascii_case("url") {
            continue; // header row
        }
        if url.starts_with("http") {
            data.urls.insert(url.to_string());
            if let Ok(parsed) = Url::parse(url) {
                if let Some(host) = parsed.host_str() {
                    if let Ok(ip) = host.parse::<IpAddr>() {
                        if !is_private_ip(&ip.to_string()) {
                            data.ips.insert(ip.to_string());
                        }
                    } else if is_valid_domain(host) {
                        data.domains.insert(host.to_lowercase());
                    }
                }
            }
        }
    }
    data
}

/// Minimal CSV line splitter that respects double-quoted fields.
fn split_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                fields.push(&line[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    fields.push(&line[start..]);
    fields
}

fn feodo_parse(raw: &str) -> FeedData {
    // FeodoTracker IP blocklist CSV columns:
    //   first_seen,dst_ip,dst_port,c2_status,last_online,malware
    // Lines starting with '#' are comments; first non-comment line is the header.
    let mut data = FeedData::default();
    let mut header_seen = false;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !header_seen {
            header_seen = true;
            continue; // skip the header row
        }
        let fields: Vec<&str> = line.splitn(6, ',').collect();
        if fields.len() < 2 {
            continue;
        }
        let ip = fields[1].trim().trim_matches('"');
        if ip.parse::<IpAddr>().is_ok() && !is_private_ip(ip) {            data.ips.insert(ip.to_string());
        }
    }
    data
}

fn phishtank_parse(raw: &str) -> FeedData {
    // PhishTank online-valid.csv columns (may vary):
    //   phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
    // We find the "url" column by header name so layout changes don't break parsing.
    let mut data = FeedData::default();
    let mut rdr = ReaderBuilder::new()
        .flexible(true)
        .from_reader(raw.as_bytes());

    let headers = match rdr.headers() {
        Ok(h) => h.clone(),
        Err(_) => return data,
    };
    let url_col = headers.iter().position(|h| h.eq_ignore_ascii_case("url"));
    let url_col = match url_col {
        Some(c) => c,
        None => return data, // unrecognised format
    };

    for result in rdr.records() {
        let rec = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let url = match rec.get(url_col) {
            Some(u) => u.trim(),
            None => continue,
        };
        if url.starts_with("http") {
            data.urls.insert(url.to_string());
            if let Ok(parsed) = Url::parse(url) {
                if let Some(host) = parsed.host_str() {
                    if is_valid_domain(host) {
                        data.domains.insert(host.to_lowercase());
                    } else if let Ok(ip) = host.parse::<IpAddr>() {
                        if !is_private_ip(&ip.to_string()) {
                            data.ips.insert(ip.to_string());
                        }
                    }
                }
            }
        }
    }
    data
}

fn bambenek_parse(raw: &str) -> FeedData {
    let mut data = FeedData::default();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let domain = line.split(',').next().unwrap_or("").trim();
        if is_valid_domain(domain) {
            data.domains.insert(domain.to_lowercase());
        }
    }
    data
}

fn blocklist_de_parse(raw: &str) -> FeedData {
    let mut data = FeedData::default();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.parse::<IpAddr>().is_ok() && !is_private_ip(line) {
            data.ips.insert(line.to_string());
        }
    }
    data
}

fn emerging_threats_parse(raw: &str) -> FeedData {
    // EmergingThreats fwrules list: one IP or CIDR per line, comments start with '#'
    // We store CIDRs directly in the `ips` set (using network address notation) to
    // avoid exploding /16 and /8 blocks into millions of entries.  Matching is done
    // by the caller via CIDR containment rather than exact set membership.
    let mut data = FeedData::default();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Accept both bare IPs and CIDR notation
        if let Ok(net) = line.parse::<ipnet::IpNet>() {
            let addr = net.addr().to_string();
            if !is_private_ip(&addr) {
                // Store as "addr/prefix" so the check_ip logic can match by CIDR
                data.ips.insert(net.to_string());
            }
        } else if let Ok(ip) = line.parse::<IpAddr>() {
            let s = ip.to_string();
            if !is_private_ip(&s) {
                data.ips.insert(s);
            }
        }
    }
    data
}

async fn otx_download(api_key: &str) -> String {
    let mut all = Vec::new();
    let client = &*HTTP_CLIENT;
    let mut page = 1;
    while page <= 5 {
        let url = format!(
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page={}",
            page
        );
        let resp = client
            .get(&url)
            .header("X-OTX-API-KEY", api_key)
            .send()
            .await;
        if let Ok(r) = resp {
            if let Ok(json) = r.json::<Value>().await {
                if let Some(results) = json.get("results").and_then(|v| v.as_array()) {
                    for pulse in results {
                        if let Some(indicators) = pulse.get("indicators").and_then(|v| v.as_array())
                        {
                            for ind in indicators {
                                all.push(ind.clone());
                            }
                        }
                    }
                }
                if json.get("next").is_none() {
                    break;
                }
            }
        }
        page += 1;
    }
    serde_json::to_string(&all).unwrap_or_default()
}

fn otx_parse(raw: &str) -> FeedData {
    let mut data = FeedData::default();
    if let Ok(indicators) = serde_json::from_str::<Vec<Value>>(raw) {
        for ind in indicators {
            let typ = ind.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let value = ind
                .get("indicator")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if value.is_empty() {
                continue;
            }
            match typ {
                "IPv4" | "IPv6" => {
                    if !is_private_ip(value) {
                        data.ips.insert(value.to_string());
                    }
                }
                "domain" | "FQDN" | "hostname" => {
                    if is_valid_domain(value) {
                        data.domains.insert(value.to_lowercase());
                    }
                }
                "URL" => {
                    if value.starts_with("http") {
                        data.urls.insert(value.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    data
}

// =============================================================================
// 5b. OTX Collector (AlienVault OTX, API-key based)
// =============================================================================
struct OtxCollector {
    api_key: String,
    cache: Arc<FeedCache>,
    force_refresh: bool,
    data: Arc<Mutex<Option<FeedData>>>,
}

impl OtxCollector {
    const FEED_ID: &'static str = "otx_alienvault";
    const TTL: u64 = 7200; // 2 h

    async fn load(&self) -> FeedData {
        {
            let guard = self.data.lock().await;
            if let Some(ref d) = *guard {
                return d.clone();
            }
        }
        if !self.force_refresh {
            if let Some(cached) = self.cache.get(Self::FEED_ID, Self::TTL) {
                let fd: FeedData = serde_json::from_value(cached).unwrap_or_default();
                *self.data.lock().await = Some(fd.clone());
                return fd;
            }
        }
        let raw = otx_download(&self.api_key).await;
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
        "OTX-AlienVault"
    }
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        let data = self.load().await;
        if data.ips.contains(ip) {
            vec![ThreatHit {
                source: self.name().to_string(),
                classification_type: "malicious-code".to_string(),
                classification_taxonomy: "malicious-code".to_string(),
                confidence: 0.80,
                details: json!({ "feed": "OTX-AlienVault" }),
            }]
        } else {
            vec![]
        }
    }
    async fn check_domain(&self, domain: &str) -> Vec<ThreatHit> {
        let data = self.load().await;
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 0..parts.len() {
            let candidate = parts[i..].join(".");
            if data.domains.contains(&candidate) {
                return vec![ThreatHit {
                    source: self.name().to_string(),
                    classification_type: "malicious-code".to_string(),
                    classification_taxonomy: "malicious-code".to_string(),
                    confidence: 0.80,
                    details: json!({ "feed": "OTX-AlienVault", "matched": candidate }),
                }];
            }
        }
        vec![]
    }
    async fn check_url(&self, url: &str) -> Vec<ThreatHit> {
        let data = self.load().await;
        for feed_url in &data.urls {
            if url == feed_url || url.starts_with(feed_url.as_str()) {
                return vec![ThreatHit {
                    source: self.name().to_string(),
                    classification_type: "malicious-code".to_string(),
                    classification_taxonomy: "malicious-code".to_string(),
                    confidence: 0.80,
                    details: json!({ "feed": "OTX-AlienVault", "matched": feed_url }),
                }];
            }
        }
        vec![]
    }
}

// =============================================================================
// 5c. Remote API Backends
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
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        {
            let cache = self.cache.lock().await;
            if let Some(hits) = cache.get(ip) {
                return hits.clone();
            }
        }
        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ip
        );
        let mut hits = Vec::new();
        if let Ok(resp) = HTTP_CLIENT
            .get(&url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
        {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(score) = json["data"]["abuseConfidenceScore"].as_u64() {
                    if score as u8 >= self.min_score {
                        hits.push(ThreatHit {
                            source: self.name().to_string(),
                            classification_type: "blacklist".to_string(),
                            classification_taxonomy: "other".to_string(),
                            confidence: score as f64 / 100.0,
                            details: json["data"].clone(),
                        });
                    }
                }
            }
        }
        self.cache.lock().await.insert(ip.to_string(), hits.clone());
        hits
    }
    async fn check_domain(&self, _domain: &str) -> Vec<ThreatHit> {
        vec![]
    }
    async fn check_url(&self, _url: &str) -> Vec<ThreatHit> {
        vec![]
    }
}

struct VirusTotalBackend {
    api_key: String,
    min_detections: u32,
    cache: Arc<Mutex<HashMap<String, Vec<ThreatHit>>>>,
}

impl VirusTotalBackend {
    async fn _lookup(&self, endpoint: &str, id: &str) -> Vec<ThreatHit> {
        let key = format!("{}/{}", endpoint, id);
        {
            let cache = self.cache.lock().await;
            if let Some(hits) = cache.get(&key) {
                return hits.clone();
            }
        }
        let url = format!("https://www.virustotal.com/api/v3/{}/{}", endpoint, id);
        let mut hits = Vec::new();
        if let Ok(resp) = HTTP_CLIENT
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
        {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(attrs) = json.get("data").and_then(|d| d.get("attributes")) {
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
                    let hits_count = mal + sus;
                    if hits_count >= self.min_detections as u64 {
                        hits.push(ThreatHit {
                            source: self.name().to_string(),
                            classification_type: if mal > 0 {
                                "malware".to_string()
                            } else {
                                "ids-alert".to_string()
                            },
                            classification_taxonomy: if mal > 0 {
                                "malicious-code".to_string()
                            } else {
                                "intrusion-attempts".to_string()
                            },
                            confidence: hits_count as f64 / total as f64,
                            details: json!({
                                "malicious": mal,
                                "suspicious": sus,
                                "total_engines": total,
                                "reputation": attrs.get("reputation").unwrap_or(&json!(0)),
                            }),
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
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        self._lookup("ip_addresses", ip).await
    }
    async fn check_domain(&self, domain: &str) -> Vec<ThreatHit> {
        self._lookup("domains", domain).await
    }
    async fn check_url(&self, url: &str) -> Vec<ThreatHit> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let encoded = URL_SAFE_NO_PAD.encode(url.as_bytes());
        self._lookup("urls", &encoded).await
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
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        {
            let cache = self.cache.lock().await;
            if let Some(hits) = cache.get(ip) {
                return hits.clone();
            }
        }
        let url = format!(
            "https://api.shodan.io/shodan/host/{}?key={}",
            ip, &self.api_key
        );
        let mut hits = Vec::new();
        if let Ok(resp) = HTTP_CLIENT.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(json) = resp.json::<Value>().await {
                    let tags = json
                        .get("tags")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|t| t.as_str()).collect::<HashSet<_>>())
                        .unwrap_or_default();
                    let dangerous_tags: Vec<&str> = tags
                        .into_iter()
                        .filter(|t| {
                            matches!(
                                *t,
                                "malware" | "c2" | "scanner" | "honeypot" | "compromised"
                            )
                        })
                        .collect();
                    let ports = json
                        .get("ports")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|p| p.as_u64()).collect::<Vec<_>>())
                        .unwrap_or_default();
                    let sus_ports: Vec<u64> = ports
                        .iter()
                        .filter(|p| SUSPICIOUS_PORTS.contains(&(**p as u16)))
                        .copied()
                        .collect();
                    if !dangerous_tags.is_empty() || !sus_ports.is_empty() {
                        hits.push(ThreatHit {
                            source: self.name().to_string(),
                            classification_type: "potentially-unwanted-accessible".to_string(),
                            classification_taxonomy: "vulnerable".to_string(),
                            confidence: 0.65,
                            details: json!({
                                "dangerous_tags": dangerous_tags,
                                "open_ports": ports,
                                "suspicious_ports": sus_ports,
                                "country": json.get("country_name").unwrap_or(&json!(null)),
                                "org": json.get("org").unwrap_or(&json!(null)),
                            }),
                        });
                    }
                }
            }
        }
        self.cache.lock().await.insert(ip.to_string(), hits.clone());
        hits
    }
    async fn check_domain(&self, _domain: &str) -> Vec<ThreatHit> {
        vec![]
    }
    async fn check_url(&self, _url: &str) -> Vec<ThreatHit> {
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
    async fn _login(&self) -> Option<String> {
        let url = format!("{}/v1/api/login/", self.base_url);
        let form = vec![
            ("username", self.username.as_str()),
            ("password", self.password.as_str()),
        ];
        if let Ok(resp) = HTTP_CLIENT
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .await
        {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(token) = json.get("login_token").and_then(|v| v.as_str()) {
                    return Some(token.to_string());
                }
            }
        }
        None
    }

    async fn _lookup(&self, field: &str, value: &str) -> Vec<ThreatHit> {
        let cache_key = format!("{}:{}", field, value);
        {
            let cache = self.cache.lock().await;
            if let Some(hits) = cache.get(&cache_key) {
                return hits.clone();
            }
        }
        // Get token without holding lock across await
        let token_opt = {
            let mut token_guard = self.token.lock().await;
            if token_guard.is_none() {
                *token_guard = self._login().await;
            }
            token_guard.clone()
        };
        let token = match token_opt {
            Some(t) => t,
            None => return vec![],
        };
        let url = format!("{}/v1/api/events?{}={}", self.base_url, field, value);
        let mut hits = Vec::new();
        if let Ok(resp) = HTTP_CLIENT
            .get(&url)
            .header("Authorization", &token)
            .send()
            .await
        {
            if let Ok(events) = resp.json::<Vec<Value>>().await {
                for ev in events {
                    let ctype = ev
                        .get("classification.type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("undetermined")
                        .to_string();
                    let ctax = ev
                        .get("classification.taxonomy")
                        .and_then(|v| v.as_str())
                        .unwrap_or("other")
                        .to_string();
                    let details = ev
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
                        source: self.name().to_string(),
                        classification_type: ctype,
                        classification_taxonomy: ctax,
                        confidence: 0.75,
                        details: Value::Object(details),
                    });
                }
            }
        }
        self.cache.lock().await.insert(cache_key, hits.clone());
        hits
    }
}

#[async_trait::async_trait]
impl ThreatIntelBackend for IntelMQBackend {
    fn name(&self) -> &'static str {
        "IntelMQ-API"
    }
    async fn check_ip(&self, ip: &str) -> Vec<ThreatHit> {
        self._lookup("source.ip", ip).await
    }
    async fn check_domain(&self, domain: &str) -> Vec<ThreatHit> {
        self._lookup("source.fqdn", domain).await
    }
    async fn check_url(&self, url: &str) -> Vec<ThreatHit> {
        self._lookup("source.url", url).await
    }
}

// =============================================================================
// 5c. Local Heuristics
// =============================================================================
struct LocalHeuristicBackend;

#[async_trait::async_trait]
impl ThreatIntelBackend for LocalHeuristicBackend {
    fn name(&self) -> &'static str {
        "LocalHeuristic"
    }
    async fn check_domain(&self, domain: &str) -> Vec<ThreatHit> {
        lazy_static::lazy_static! {
            static ref PATTERNS: Vec<(Regex, &'static str, f64)> = vec![
                (Regex::new(r"^[a-z0-9]{16,}\.[a-z]{2,4}$").unwrap(), "Long random label — possible DGA", 0.55),
                (Regex::new(r"^[a-z0-9]{8,}\.(xyz|top|tk|ml|ga|cf|gq|pw)$").unwrap(), "DGA-like + cheap TLD", 0.65),
                (Regex::new(r"^[a-z]{3,6}[0-9]{4,}\.[a-z]{2,4}$").unwrap(), "Alphanumeric mix — possible DGA", 0.50),
            ];
        }
        for (re, reason, conf) in PATTERNS.iter() {
            if re.is_match(domain) {
                return vec![ThreatHit {
                    source: self.name().to_string(),
                    classification_type: "dga-domain".to_string(),
                    classification_taxonomy: "malicious-code".to_string(),
                    confidence: *conf,
                    details: json!({ "reason": reason }),
                }];
            }
        }
        vec![]
    }
    async fn check_ip(&self, _ip: &str) -> Vec<ThreatHit> {
        vec![]
    }
    async fn check_url(&self, _url: &str) -> Vec<ThreatHit> {
        vec![]
    }
}

// =============================================================================
// 6. Analysis Engine
// =============================================================================
struct Analyser {
    backends: Vec<Arc<dyn ThreatIntelBackend>>,
    rate_limit_ms: u64,
    verbose: bool,
}

impl Analyser {
    async fn analyse(&self, observables: &[Observable]) -> Vec<ThreatMatch> {
        let mut matches = Vec::new();
        for obs in observables {
            if self.verbose {
                eprintln!(
                    "[verbose] checking {} '{}' (seen {} time(s), ctx: {})",
                    obs.kind, obs.value, obs.count, obs.context
                );
            }
            for backend in &self.backends {
                let hits = match obs.kind.as_str() {
                    "ip" => backend.check_ip(&obs.value).await,
                    "domain" => backend.check_domain(&obs.value).await,
                    "url" => backend.check_url(&obs.value).await,
                    _ => vec![],
                };
                if self.verbose && !hits.is_empty() {
                    eprintln!(
                        "[verbose]  → {} hit(s) from backend '{}'",
                        hits.len(),
                        backend.name()
                    );
                }
                for hit in hits {
                    matches.push(ThreatMatch {
                        observable: obs.clone(),
                        ti_source: hit.source,
                        classification_type: hit.classification_type,
                        classification_taxonomy: hit.classification_taxonomy,
                        confidence: hit.confidence,
                        details: hit.details,
                    });
                }
                if self.rate_limit_ms > 0 {
                    sleep(Duration::from_millis(self.rate_limit_ms)).await;
                }
            }
        }
        matches
    }
}

// =============================================================================
// 7. Reporting & Export
// =============================================================================
fn print_report(matches: &[ThreatMatch], _observables: &[Observable]) {
    if matches.is_empty() {
        println!("{}", "✅ No threats detected.".green().bold());
        return;
    }
    println!("\n{}", "═══ Threat Intelligence Matches ═══".cyan().bold());
    println!(
        "{:<14} {:<32} {:<10} {:<18} {:>4}  {}",
        "Source", "Observable", "Kind", "Classification", "Conf", "Detail"
    );
    println!("{}", "─".repeat(100).dimmed());

    for m in matches.iter().take(50) {
        let percent = (m.confidence * 100.0) as usize;
        let conf_str = format!("{:>3}%", percent);
        let conf_colored = if percent >= 75 {
            conf_str.red().bold()
        } else if percent >= 45 {
            conf_str.yellow()
        } else {
            conf_str.cyan()
        };
        let detail = m
            .details
            .get("reason")
            .or_else(|| m.details.get("matched"))
            .or_else(|| m.details.get("matched_cidr"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!(
            "{:<14} {:<32} {:<10} {:<18} {}  {}",
            m.ti_source,
            truncate(&m.observable.value, 31),
            m.observable.kind,
            truncate(&m.classification_type, 17),
            conf_colored,
            detail,
        );
    }
    if matches.len() > 50 {
        println!(
            "{}",
            format!("  … and {} more matches (use --output-json for full results)", matches.len() - 50).dimmed()
        );
    }

    // Summary
    let high = matches.iter().filter(|m| m.confidence >= 0.75).count();
    let med  = matches.iter().filter(|m| m.confidence >= 0.45 && m.confidence < 0.75).count();
    let low  = matches.iter().filter(|m| m.confidence < 0.45).count();
    println!("\n{}", "─".repeat(100).dimmed());
    println!(
        "Total matches: {}   {} high   {} medium   {} low",
        matches.len().to_string().bold(),
        high.to_string().red(),
        med.to_string().yellow(),
        low.to_string().cyan()
    );
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn export_json(matches: &[ThreatMatch], observables: &[Observable], path: &str) -> Result<()> {
    let out = json!({
        "tool": TOOL_NAME,
        "version": VERSION,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "observables": observables,
        "threat_matches": matches,
    });
    fs::write(path, serde_json::to_string_pretty(&out)?)?;
    Ok(())
}

fn export_csv(matches: &[ThreatMatch], path: &str) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(&[
        "observable",
        "kind",
        "source_file",
        "ti_source",
        "classification_type",
        "classification_taxonomy",
        "confidence",
        "details",
    ])?;
    for m in matches {
        wtr.write_record(&[
            &m.observable.value,
            &m.observable.kind,
            &m.observable.source_file,
            &m.ti_source,
            &m.classification_type,
            &m.classification_taxonomy,
            &format!("{:.2}", m.confidence),
            &serde_json::to_string(&m.details).unwrap_or_default(),
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

// =============================================================================
// 8. CLI and Main
// =============================================================================
fn build_cli() -> Command {
    Command::new(TOOL_NAME)
        .version(VERSION)
        .about("Analyse PCAP files with IntelMQ-compatible threat intelligence (full Rust version)")
        .arg(
            Arg::new("pcap_files")
                .required(true)
                .num_args(1..)
                .help("PCAP/CAP files"),
        )
        .arg(
            Arg::new("workers")
                .long("workers")
                .default_value("4")
                .help("Parallel workers"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("refresh-feeds")
                .long("refresh-feeds")
                .action(ArgAction::SetTrue),
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
                .default_value("0.2"),
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

async fn run() -> Result<()> {
    let cli = build_cli();
    let args = cli.get_matches();

    let pcap_files: Vec<PathBuf> = args
        .get_many::<String>("pcap_files")
        .unwrap()
        .map(|s| PathBuf::from(s))
        .collect();
    let workers: usize = args
        .get_one::<String>("workers")
        .unwrap()
        .parse()
        .unwrap_or(4);
    let quiet = args.get_flag("quiet");
    let verbose = args.get_flag("verbose");
    let refresh_feeds = args.get_flag("refresh-feeds");
    let cache_dir = PathBuf::from(args.get_one::<String>("cache-dir").unwrap());
    let include_private = args.get_flag("include-private");
    let kinds_str = args.get_one::<String>("kinds").unwrap();
    let kinds: HashSet<String> = kinds_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let output_json = args.get_one::<String>("output-json").cloned();
    let output_csv = args.get_one::<String>("output-csv").cloned();
    let rate_limit_secs: f64 = args
        .get_one::<String>("rate-limit")
        .unwrap()
        .parse()
        .unwrap_or(0.2);
    let rate_limit_ms = (rate_limit_secs * 1000.0) as u64;

    // Build feed cache
    let cache = Arc::new(FeedCache::new(cache_dir.clone()));
    if verbose && !quiet {
        eprintln!(
            "[verbose] cache dir: {}",
            cache_dir.display()
        );
    }

    // Build backends vector
    let mut backends: Vec<Arc<dyn ThreatIntelBackend>> = Vec::new();

    // Feeds (unless disabled)
    if !args.get_flag("no-urlhaus") {
        let feed = FeedCollector::new(
            "URLhaus",
            "urlhaus",
            "https://urlhaus.abuse.ch/downloads/csv/".to_string(),
            3600,
            cache.clone(),
            refresh_feeds,
            "malware-distribution",
            "malicious-code",
            0.90,
            "malware-distribution",
            "malicious-code",
            0.90,
            "malware-distribution",
            "malicious-code",
            0.90,
            urlhaus_parse,
        );
        backends.push(Arc::new(feed));
    }
    if !args.get_flag("no-feodo") {
        let feed = FeedCollector::new(
            "FeodoTracker",
            "feodo_tracker",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv".to_string(),
            3600,
            cache.clone(),
            refresh_feeds,
            "c2-server",
            "malicious-code",
            0.95,
            "",
            "",
            0.0,
            "",
            "",
            0.0,
            feodo_parse,
        );
        backends.push(Arc::new(feed));
    }
    if !args.get_flag("no-phishtank") {
        let api_key = args
            .get_one::<String>("phishtank-key")
            .cloned()
            .unwrap_or_default();
        let url = if api_key.is_empty() {
            "https://data.phishtank.com/data/online-valid.csv".to_string()
        } else {
            format!(
                "https://data.phishtank.com/data/{}/online-valid.csv",
                api_key
            )
        };
        let feed = FeedCollector::new(
            "PhishTank",
            "phishtank",
            url,
            3600,
            cache.clone(),
            refresh_feeds,
            "",
            "",
            0.0,
            "phishing",
            "fraud",
            0.92,
            "phishing",
            "fraud",
            0.92,
            phishtank_parse,
        );
        backends.push(Arc::new(feed));
    }
    if !args.get_flag("no-bambenek") {
        let feed = FeedCollector::new(
            "Bambenek",
            "bambenek_c2",
            "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt".to_string(),
            3600,
            cache.clone(),
            refresh_feeds,
            "",
            "",
            0.0,
            "c2-server",
            "malicious-code",
            0.88,
            "",
            "",
            0.0,
            bambenek_parse,
        );
        backends.push(Arc::new(feed));
    }
    if !args.get_flag("no-blocklist-de") {
        let feed = FeedCollector::new(
            "Blocklist.de",
            "blocklist_de",
            "https://lists.blocklist.de/lists/all.txt".to_string(),
            43200,
            cache.clone(),
            refresh_feeds,
            "brute-force",
            "intrusion-attempts",
            0.80,
            "",
            "",
            0.0,
            "",
            "",
            0.0,
            blocklist_de_parse,
        );
        backends.push(Arc::new(feed));
    }
    if !args.get_flag("no-emerging-threats") {
        let feed = FeedCollector::new(
            "EmergingThreats",
            "emerging_threats",
            "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt".to_string(),
            86400,
            cache.clone(),
            refresh_feeds,
            "infected-system",
            "malicious-code",
            0.82,
            "",
            "",
            0.0,
            "",
            "",
            0.0,
            emerging_threats_parse,
        );
        backends.push(Arc::new(feed));
    }
    if let Some(otx_key) = args.get_one::<String>("otx-key").cloned() {
        // OTX: download pulses at startup and parse into a FeedCollector-style FeedData.
        // We use a dedicated OTX collector that fetches via the API and reuses the cache.
        let otx_cache = cache.clone();
        let otx_feed = OtxCollector {
            api_key: otx_key,
            cache: otx_cache,
            force_refresh: refresh_feeds,
            data: Arc::new(Mutex::new(None)),
        };
        backends.push(Arc::new(otx_feed));
    }

    // Remote API backends
    if let Some(key) = args.get_one::<String>("abuseipdb-key") {
        let min_score: u8 = args
            .get_one::<String>("abuseipdb-min-score")
            .unwrap()
            .parse()
            .unwrap_or(25);
        let backend = AbuseIPDBBackend {
            api_key: key.clone(),
            min_score,
            cache: Arc::new(Mutex::new(HashMap::new())),
        };
        backends.push(Arc::new(backend));
    }
    if let Some(key) = args.get_one::<String>("virustotal-key") {
        let min_detections: u32 = args
            .get_one::<String>("virustotal-min-detections")
            .unwrap()
            .parse()
            .unwrap_or(2);
        let backend = VirusTotalBackend {
            api_key: key.clone(),
            min_detections,
            cache: Arc::new(Mutex::new(HashMap::new())),
        };
        backends.push(Arc::new(backend));
    }
    if let Some(key) = args.get_one::<String>("shodan-key") {
        let backend = ShodanBackend {
            api_key: key.clone(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        };
        backends.push(Arc::new(backend));
    }
    if let (Some(url), Some(user), Some(pass)) = (
        args.get_one::<String>("intelmq-url"),
        args.get_one::<String>("intelmq-user"),
        args.get_one::<String>("intelmq-pass"),
    ) {
        let backend = IntelMQBackend {
            base_url: url.clone(),
            username: user.clone(),
            password: pass.clone(),
            token: Arc::new(Mutex::new(None)),
            cache: Arc::new(Mutex::new(HashMap::new())),
        };
        backends.push(Arc::new(backend));
    }
    if !args.get_flag("no-heuristics") {
        backends.push(Arc::new(LocalHeuristicBackend));
    }

    if !quiet {
        println!("{} {} (Rust multicore)", TOOL_NAME, VERSION);
        println!(
            "Backends: {}",
            backends
                .iter()
                .map(|b| b.name())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if verbose {
            println!(
                "[verbose] cache-dir: {}  rate-limit: {}ms  workers: {}  kinds: {:?}",
                args.get_one::<String>("cache-dir").unwrap(),
                rate_limit_ms,
                workers,
                {
                    let mut ks: Vec<_> = kinds.iter().collect();
                    ks.sort();
                    ks
                }
            );
            println!(
                "[verbose] include-private: {}  refresh-feeds: {}",
                include_private, refresh_feeds
            );
            // Print cache age for each local feed
            for feed_id in &["urlhaus", "feodo_tracker", "phishtank", "bambenek_c2",
                              "blocklist_de", "emerging_threats", "otx_alienvault"] {
                let age = cache.age_str(feed_id);
                eprintln!("[verbose] feed cache '{}': {}", feed_id, age);
            }
        }
    }

    // Extract observables in parallel
    if !quiet {
        println!(
            "Extracting observables from {} file(s) using {} workers...",
            pcap_files.len(),
            workers
        );
    }
    let pb = if !quiet {
        let pb = ProgressBar::new(pcap_files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} files  {msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ "),
        );
        Some(pb)
    } else {
        None
    };

    // Use rayon for parallel extraction
    let all_obs: Vec<Observable> = pcap_files
        .par_iter()
        .flat_map(|path| {
            if verbose && !quiet {
                eprintln!("[verbose] extracting: {}", path.display());
            }
            let result = extract_observables_from_pcap(path, include_private, &kinds)
                .unwrap_or_else(|e| {
                    eprintln!("{} extracting {}: {}", "ERROR".red().bold(), path.display(), e);
                    vec![]
                });
            if verbose && !quiet {
                eprintln!("[verbose] {} → {} observables", path.display(), result.len());
            }
            if let Some(pb) = &pb {
                pb.inc(1);
            }
            result
        })
        .collect();

    if let Some(pb) = pb {
        pb.finish();
    }

    // Deduplicate
    let mut dedup_map = HashMap::new();
    for o in all_obs {
        let key = format!("{}:{}", o.kind, o.value);
        dedup_map
            .entry(key)
            .and_modify(|e: &mut Observable| e.count += o.count)
            .or_insert(o);
    }
    let unique_obs: Vec<Observable> = dedup_map.into_values().collect();

    if unique_obs.is_empty() {
        if !quiet {
            println!("No analyzable observables found.");
        }
        return Ok(());
    }
    if !quiet {
        let ip_count = unique_obs.iter().filter(|o| o.kind == "ip").count();
        let dom_count = unique_obs.iter().filter(|o| o.kind == "domain").count();
        let url_count = unique_obs.iter().filter(|o| o.kind == "url").count();
        println!(
            "Unique observables: {} (IPs: {}, domains: {}, URLs: {})",
            unique_obs.len(), ip_count, dom_count, url_count
        );
        println!("Running lookups across {} backend(s)...", backends.len());
    }

    let analyser = Analyser {
        backends,
        rate_limit_ms,
        verbose: verbose && !quiet,
    };
    let matches = analyser.analyse(&unique_obs).await;

    if !quiet {
        print_report(&matches, &unique_obs);
    }
    if let Some(path) = output_json {
        export_json(&matches, &unique_obs, &path)?;
        if !quiet {
            println!("JSON exported to {}", path);
        }
    }
    if let Some(path) = output_csv {
        export_csv(&matches, &path)?;
        if !quiet {
            println!("CSV exported to {}", path);
        }
    }

    Ok(())
}