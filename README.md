# pcap2api-rs

> Analyse network captures against threat intelligence feeds — no SIEM required.  
> **Rust multicore edition — parallel PCAP extraction, low memory, single static binary.**

`pcap2api` extracts IPs, domains, and URLs from one or more PCAP/CAP files and cross-references them against seven public threat intelligence feeds plus optional commercial APIs. It mirrors the **IntelMQ Collector → Parser → Output pipeline** in a single, self-contained command-line tool.

```
$ pcap2api ./2021-0* --verbose
pcap2api v2.1.0  (Rust · 7 backends)

Extracting observables from 10 file(s) with 4 workers…
Unique observables: 800  (IPs: 106  domains: 144  URLs: 550)
[00:00:06] ████████████████████████████████████████  5600/5600 checks  hits:12

  ▶  2021-08-16-formbook.pcap   [24 ip  35 domain  130 url]  →  1 match(es) on 1 observable(s)
  ▶  2021-08-17-formbook.pcap   [17 ip  36 domain   96 url]  →  5 match(es) on 5 observable(s)
  ▶  2021-08-19-redline-2.pcap  [ 5 ip   2 domain    9 url]  →  1 match(es) on 1 observable(s)
  ▶  2021-08-19-redline.pcap    [ 9 ip   3 domain   18 url]  →  clean
  ▶  2021-08-20-formbook.pcap   [11 ip  18 domain   60 url]  →  1 match(es) on 1 observable(s)

════════════════════════════════════════════════════════════════════════════
  pcap2api v2.1.0  —  Consolidated Report  (10 file(s))
════════════════════════════════════════════════════════════════════════════
  Observables : 800 total  (106 IP, 144 DOM, 550 URL)
  Backends    : URLhaus · FeodoTracker · PhishTank · Bambenek · Blocklist.de · EmergingThreats · LocalHeuristic
  Threats     : 12 match(es) on 12 unique observable(s)  [ 6 HIGH  6 MED  0 LOW ]

─── Threat Matches ─────────────────────────────────────────────────────────
  SEV     TYPE   OBSERVABLE              TI SOURCE       CLASS.TYPE        CONF  KEY DETAIL
  ─────────────────────────────────────────────────────────────────────────────────────────
   HIGH    IP    49.156.179.85           EmergingThreats infected-system    82%  49.156.160.0/19
   HIGH    DOM   www.linkedin.com        PhishTank       phishing           92%  www.linkedin.com
    MED    DOM   hypercustom.top         LocalHeuristic  dga-domain         65%  DGA-like + cheap TLD
    MED    DOM   bearcreekcattlebeef.com LocalHeuristic  dga-domain         55%  Long random label

─── Flagged Observables ────────────────────────────────────────────────────
  TYPE   VALUE                    CONTEXT     COUNT  FILE              SOURCES
  ───────────────────────────────────────────────────────────────────────────
   IP    49.156.179.85            destination    73  2021-08-20-for…   EmergingThreats
   DOM   hypercustom.top          dns-query      25  2021-08-19-red…   LocalHeuristic
   DOM   www.linkedin.com         http-host       6  2021-08-17-for…   PhishTank
```

---

## Features

### Seven built-in threat intelligence feeds

The tool emulates the IntelMQ **Collector → Parser → Cache → Lookup** pipeline for each feed. Each feed is downloaded automatically, parsed into in-memory hash sets, and cached on disk. No API keys required for the six public feeds.

| Feed | What it detects | TTL | Key note |
|---|---|---|---|
| **URLhaus** (Abuse.ch) | Malware distribution URLs and their hosting IPs | 60 min | |
| **Feodo Tracker** (Abuse.ch) | Active botnet C2 IPs (Emotet, TrickBot, QakBot…) | 60 min | |
| **PhishTank** | Verified phishing URLs and domains | 60 min | API key optional (raises rate limit) |
| **Bambenek Consulting** | C2 domains and DGA masterlist | 60 min | Returns HTTP 403 without registration |
| **Blocklist.de** | IPs with SSH/FTP/SMTP brute-force history | 12 h | Volunteer service — large file |
| **Emerging Threats** (Proofpoint) | Botnet and C2 IPs, CIDR-aware | 24 h | CIDRs stored directly — no host expansion |
| **AlienVault OTX** | Community threat pulses: IPs, domains, URLs | 30 min | Free API key required |

> **On Bambenek:** The public feed URL (`c2-dommasterlist-high.txt`) now returns HTTP 403 without registration. The tool handles this gracefully — it prints a targeted warning and falls back to stale cache if available. Use `--no-bambenek` to disable it entirely if you don't have access.

### Observable extraction from PCAP

Files are streamed one packet at a time (no full load into memory), making the tool suitable for large captures.

| Observable | Extraction method |
|---|---|
| **IPs** | IPv4/IPv6 headers — both source and destination |
| **Domains** | DNS query names from DNSQR layer |
| **URLs** | Reconstructed from HTTP payloads (`Host:` header + request line) |
| **Ports** | TCP/UDP destination ports, flagged if in the known-malicious set |

### Consolidated per-file reporting

Each file is summarised immediately after extraction. A full consolidated report is printed at the end, including:

- **Threat Matches** table — severity badge (`HIGH`/`MED`/`LOW`), asset type badge (`IP`/`DOM`/`URL`), TI source, classification type and taxonomy, confidence, and key detail
- **Flagged Observables** table — context (dns-query, http-host, source, destination…), packet count, source file, and which backends flagged it
- **Feed Status** table — TTL, cache age, and remote vs. local classification for every backend

### Local disk cache with TTL management

Feeds are stored under `~/.cache/pcap2api/`. Each feed's recommended refresh interval is enforced. Use `--refresh-feeds` to force an immediate re-download. On network failure the tool falls back to the most recent stale cache entry and tells you its age.

### Optional remote API backends

| Backend | Checks | Key note |
|---|---|---|
| **AbuseIPDB** | IP reputation | Configurable minimum confidence score |
| **VirusTotal** | IPs, domains, URLs | Configurable minimum engine detections |
| **Shodan** | Open ports, dangerous host tags | Flags known-malicious tags (c2, scanner, honeypot…) |
| **IntelMQ REST API** | IPs, FQDNs, URLs | Queries a live IntelMQ event store |

Rate limiting (default 200 ms) applies **only** to remote API backends. Local feed lookups run at full in-memory speed.

### Local heuristics

- **DGA domain detection** — regex patterns for long random labels, alphanumeric mixes, and cheap TLDs (`.xyz`, `.top`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.pw`)
- **Suspicious port flagging** — 4444, 1337, 31337, 9050, 9051, and more

### Output formats

- **Colour terminal report** — severity and asset type colour-coded badges, per-file summaries, consolidated report
- **JSON** — full structured report with summary metadata, all observables, and all matches
- **CSV** — 20 columns including `severity`, `asset_type`, `asset_context`, `asset_count`, plus expanded detail columns per backend (abuse score, ISP, country, VT engine counts, Shodan tags…)
- **Exit code 1** if threats found, 0 if clean — CI/CD pipeline friendly

---

## Installation

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Install system dependencies

**Ubuntu / Debian / Kali**
```bash
sudo apt update && sudo apt install -y libpcap-dev build-essential
```

**Fedora / RHEL / CentOS Stream**
```bash
sudo dnf install -y libpcap-devel gcc
```

**Arch Linux / Manjaro**
```bash
sudo pacman -S libpcap base-devel
```

### 3. Build

```bash
git clone https://github.com/guilhermegui08/pcap2api-rs
cd pcap2api
cargo build --release
```

The binary is at `target/release/pcap2api`. Copy it to your `$PATH`:

```bash
cp target/release/pcap2api ~/.local/bin/
```

> **Permissions:** Reading PCAPs captured on a live interface may require `sudo` or membership in the `pcap` group (`sudo usermod -aG pcap $USER`, then log out and back in).

---

## Usage

### Scan with all built-in feeds (no keys needed)

```bash
pcap2api capture.pcap
```

### Multiple files — processed in parallel, single consolidated report

```bash
pcap2api morning.pcap afternoon.cap night.pcapng
```

### Force a fresh feed download (ignore cache)

```bash
pcap2api capture.pcap --refresh-feeds
```

### Add AlienVault OTX

```bash
pcap2api capture.pcap --otx-key YOUR_OTX_KEY
```

### Full stack — all feeds + remote APIs + exports

```bash
pcap2api a.pcap b.cap \
    --otx-key        OTX_KEY   \
    --abuseipdb-key  AIPDB_KEY \
    --virustotal-key VT_KEY    \
    --shodan-key     SHODAN_KEY \
    --output-json report.json  \
    --output-csv  report.csv   \
    --verbose
```

### Disable feeds that are unavailable or not needed

```bash
pcap2api capture.pcap --no-bambenek --no-blocklist-de
```

### CI/CD — fail the pipeline if threats are found

```bash
pcap2api capture.pcap --quiet
echo "Exit: $?"   # 0 = clean, 1 = threats detected
```

### Use a custom cache directory

```bash
pcap2api capture.pcap --cache-dir /var/cache/pcap2api
```

---

## Environment variables

| Variable | Backend |
|---|---|
| `OTX_KEY` | AlienVault OTX |
| `PHISHTANK_KEY` | PhishTank (optional, raises rate limit) |
| `ABUSEIPDB_KEY` | AbuseIPDB |
| `VIRUSTOTAL_KEY` | VirusTotal |
| `SHODAN_KEY` | Shodan |

```bash
export ABUSEIPDB_KEY=your_key
pcap2api capture.pcap
```

---

## Full option reference

```
Usage: pcap2api [OPTIONS] <FILE.pcap>...

Arguments:
  <FILE.pcap>...  One or more PCAP/CAP capture files to analyse

General:
      --workers <N>          Parallel extraction workers [default: 4]
  -v, --verbose              Show per-check detail and feed download progress
  -q, --quiet                Suppress all output except errors (exit code only)
      --refresh-feeds        Force re-download of all feeds, ignoring TTL cache
      --cache-dir <DIR>      Feed cache directory [default: ~/.cache/pcap2api]
      --include-private      Include private/RFC1918 IPs in lookups
      --kinds <KIND>...      Observable kinds to look up [default: ip domain url]
      --rate-limit <SECS>    Pause between remote API calls [default: 0.2]

Output:
      --output-json <FILE>   Save full results to a JSON file
      --output-csv  <FILE>   Save threat matches to a CSV file (20 columns)

Feed collectors (all enabled by default):
      --no-urlhaus           Disable URLhaus feed
      --no-feodo             Disable Feodo Tracker feed
      --no-phishtank         Disable PhishTank feed
      --no-bambenek          Disable Bambenek feed
      --no-blocklist-de      Disable Blocklist.de feed
      --no-emerging-threats  Disable Emerging Threats feed
      --no-heuristics        Disable local DGA / suspicious-port heuristics
      --otx-key <KEY>        AlienVault OTX API key  (env: OTX_KEY)
      --phishtank-key <KEY>  PhishTank API key        (env: PHISHTANK_KEY)

Remote API backends (disabled unless key is provided):
      --abuseipdb-key <KEY>                AbuseIPDB v2 API key       (env: ABUSEIPDB_KEY)
      --abuseipdb-min-score <N>            Minimum confidence score   [default: 25]
      --virustotal-key <KEY>               VirusTotal v3 API key      (env: VIRUSTOTAL_KEY)
      --virustotal-min-detections <N>      Minimum engine detections  [default: 2]
      --shodan-key <KEY>                   Shodan API key             (env: SHODAN_KEY)
      --intelmq-url  <URL>                 IntelMQ REST API base URL
      --intelmq-user <USER>                IntelMQ REST API username
      --intelmq-pass <PASS>                IntelMQ REST API password

  -h, --help     Print help
  -V, --version  Print version
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No threats detected |
| `1` | One or more threat matches found |
| `2` | Argument or file error |

---

## CSV column reference

The `--output-csv` file contains 20 columns:

| Column | Description |
|---|---|
| `asset_type` | `ip`, `domain`, or `url` |
| `asset_value` | The observable value |
| `asset_context` | How it was extracted: `dns-query`, `http-host`, `source`, `destination`… |
| `asset_count` | Number of packets containing this observable |
| `source_file` | PCAP file it came from |
| `ti_source` | Backend that flagged it (URLhaus, PhishTank, etc.) |
| `classification_type` | IntelMQ/RSIT type (c2-server, phishing, brute-force…) |
| `classification_taxonomy` | IntelMQ/RSIT taxonomy (malicious-code, fraud, intrusion-attempts…) |
| `severity` | `HIGH`, `MED`, or `LOW` (derived from confidence) |
| `confidence_pct` | Integer 0–100 |
| `detail_matched` | Exact value matched (CIDR block, URL prefix, parent domain…) |
| `detail_reason` | Heuristic reason text |
| `detail_abuse_score` | AbuseIPDB confidence score |
| `detail_isp` | AbuseIPDB — ISP of the IP |
| `detail_country` | AbuseIPDB / Shodan country |
| `detail_malicious_engines` | VirusTotal — malicious engine count |
| `detail_suspicious_engines` | VirusTotal — suspicious engine count |
| `detail_total_engines` | VirusTotal — total engine count |
| `detail_dangerous_tags` | Shodan — dangerous host tags |
| `detail_suspicious_ports` | Shodan — open suspicious ports |
| `details_json` | Full raw details blob (catch-all) |

---

## Design notes

**Why not use IntelMQ directly?**
IntelMQ is a full pipeline platform requiring Redis, multiple processes, and YAML configuration. This tool is for analysts who need quick, ad-hoc PCAP analysis without standing up infrastructure — one binary, one command.

**Feed selection rationale**
The feeds were chosen to cover the main threat categories without redundancy: malware distribution (URLhaus), active botnets and C2 (Feodo Tracker, Bambenek), phishing (PhishTank), opportunistic attackers (Blocklist.de), broad IP coverage (Emerging Threats), and community intelligence (OTX). Together they cover the most common malware families seen in real-world captures, as demonstrated by the included test results against Formbook, RedLine, LokiBot, and SquirrelWaffle samples.

**Cache and rate limiting design**
Rate limiting (configurable via `--rate-limit`) applies only to remote API backends that enforce terms of service. Local feed lookups — which are hash-set membership tests — run without any delay. Feed TTLs are set conservatively to respect volunteer-operated services (Blocklist.de at 12 h, Emerging Threats at 24 h).

**Memory design**
Emerging Threats stores CIDR blocks as `ipnet::IpNet` objects rather than expanding them to individual host IPs, which would generate hundreds of millions of entries. All other feeds use `HashSet<String>` with O(1) lookup. Observable extraction streams packets one at a time via libpcap so even multi-gigabyte captures never fully enter memory.

**Classification taxonomy**
All matches use the [IntelMQ Data Harmonisation](https://docs.intelmq.org/latest/dev/data-format/) / [RSIT](https://github.com/enisaeu/Reference-Security-Incident-Taxonomy-Task-Force/) ontology (`classification.type` and `classification.taxonomy`), making output directly compatible with IntelMQ event stores and MISP.

---

## Acknowledgements

- [IntelMQ](https://github.com/certtools/intelmq) — for the data harmonisation ontology and feed architecture that inspired this tool
- [Abuse.ch](https://abuse.ch) — URLhaus and Feodo Tracker
- [PhishTank](https://www.phishtank.com)
- [Bambenek Consulting](https://osint.bambenekconsulting.com)
- [Blocklist.de](https://www.blocklist.de)
- [Proofpoint Emerging Threats](https://rules.emergingthreats.net)
- [AlienVault OTX](https://otx.alienvault.com)

---

## License

GPLv3 — see [LICENSE](LICENSE).
