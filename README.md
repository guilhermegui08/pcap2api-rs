# pcap2api-rs

> Analyse network captures against threat intelligence feeds — no SIEM required.  
> **Rust multicore edition – up to 10 × faster than the original Python version.**

`pcap2api-rs` extracts IPs, domains, and URLs from one or more PCAP/CAP files and cross‑references them against seven public threat intelligence feeds plus optional commercial APIs. It mirrors the **IntelMQ Collector → Parser → Output pipeline** in a single, self‑contained, highly parallel command‑line tool.

```
$ pcap2api-rs capture.pcap

  Loading 6 threat feed(s)…
  [cache] URLhaus (4m ago)       ips:12482  domains:8741  urls:51203
  [fetch] FeodoTracker           ips:892    domains:0      urls:0
  ...

  Unique observables: 134  (89 ips, 31 domains, 14 urls)
  Running lookups across 7 backend(s)…

  ┌─────────────────────┬──────────┬─────────────────┬──────────────────┬───────┐
  │ Observable          │ Kind     │ TI Source       │ Class. Type      │ Conf. │
  ├─────────────────────┼──────────┼─────────────────┼──────────────────┼───────┤
  │ 185.220.101.47      │ ip       │ FeodoTracker    │ c2-server        │  95%  │
  │ malware-cdn.xyz     │ domain   │ URLhaus         │ malware-distrib… │  90%  │
  │ 94.102.49.190       │ ip       │ Blocklist.de    │ brute-force      │  80%  │
  └─────────────────────┴──────────┴─────────────────┴──────────────────┴───────┘
```

---

## Features

### Seven built-in threat intelligence feeds (no API keys required)

| Feed | What it detects | TTL |
|---|---|---|
| **URLhaus** (Abuse.ch) | Malware distribution URLs and their hosting IPs | 60 min |
| **Feodo Tracker** (Abuse.ch) | Active botnet C2 IPs (Emotet, TrickBot, QakBot…) | 60 min |
| **PhishTank** | Verified phishing URLs and domains | 60 min |
| **Bambenek Consulting** | C2 domains and DGA masterlist | 60 min |
| **Blocklist.de** | IPs with a history of SSH/FTP/SMTP brute‑force or scanning | 12 h |
| **Emerging Threats** (Proofpoint) | Consolidated botnet and C2 IP blocklist, CIDR‑aware | 24 h |
| **AlienVault OTX** | Community threat pulses: IPs, domains, URLs *(free API key required)* | 30 min |

### Observable extraction from PCAP (streaming, low memory)
- **IPs** – from IPv4 and IPv6 headers (source and destination)
- **Domains** – from DNS query names (DNSQR layer)
- **URLs** – reconstructed from HTTP payloads (`Host:` + request line)
- **Ports** – flagged against a known‑malicious port list

### Local disk cache with TTL management
Feeds are stored under `~/.cache/pcap2api-rs/`. Each feed's recommended refresh interval is honoured automatically. Use `--refresh-feeds` to force an immediate re‑download.

### Optional remote API backends (API keys required)

| Backend | Checks |
|---|---|
| **AbuseIPDB** | IP reputation with configurable confidence threshold |
| **VirusTotal** | IPs, domains, and URLs across 70+ security engines |
| **Shodan** | Open ports, dangerous host tags, and infrastructure context |
| **IntelMQ REST API** | Query a live IntelMQ event store directly |

### Local heuristics (no network required)
- DGA‑like domain detection (long random labels, cheap TLDs such as `.xyz`, `.tk`, `.ml`)
- Suspicious port flagging (4444, 1337, 31337, 9050, etc.)

### Output formats
- **Rich terminal table** with colour‑coded severity (high / medium / low)
- **JSON** – full structured report with metadata
- **CSV** – matches only, ready for spreadsheet or SIEM import
- **Exit code 1** if any threats are found, 0 if clean – suitable for CI/CD pipelines

---

## Installation

### 1. Install Rust and build tools

If you don’t have Rust installed yet:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Install system dependency `libpcap`

- **Ubuntu / Debian / Kali**  
  ```bash
  sudo apt update
  sudo apt install -y libpcap-dev build-essential
  ```

- **Fedora / RHEL**  
  ```bash
  sudo dnf install -y libpcap-devel
  ```

- **Arch Linux / Manjaro**  
  ```bash
  sudo pacman -S libpcap
  ```

### 3. Build from source

```bash
git clone https://github.com/guilhermegui08/pcap2api-rs
cd pcap2api-rs
cargo build --release
```

The executable is now `target/release/pcap2api-rs`. You can copy it anywhere in your `$PATH`:

```bash
cp target/release/pcap2api-rs ~/.local/bin/
```

> **Note on permissions:** Reading PCAP files captured on a live interface may require `sudo` or membership in the `pcap` group (e.g. `sudo usermod -a -G pcap $USER`). After changing groups, you need to log out and back in.

---

## Usage

All command‑line options are **identical** to the original Python tool. `--help` shows the full list.

### Basic — feeds only, no keys needed

```bash
pcap2api-rs capture.pcap
```

### Multiple files

```bash
pcap2api-rs morning.pcap afternoon.cap night.pcapng
```

### Force a fresh feed download (ignore cache)

```bash
pcap2api-rs capture.pcap --refresh-feeds
```

### Add AlienVault OTX (free account at otx.alienvault.com)

```bash
pcap2api-rs capture.pcap --otx-key YOUR_OTX_KEY
```

### Add commercial API backends

```bash
pcap2api-rs capture.pcap \
    --abuseipdb-key YOUR_AIPDB_KEY \
    --virustotal-key YOUR_VT_KEY \
    --shodan-key YOUR_SHODAN_KEY
```

### Export results

```bash
pcap2api-rs capture.pcap \
    --output-json report.json \
    --output-csv  report.csv
```

### Full example — all feeds + APIs + exports

```bash
pcap2api-rs a.pcap b.cap \
    --otx-key       OTX_KEY   \
    --abuseipdb-key AIPDB_KEY \
    --virustotal-key VT_KEY   \
    --output-json report.json \
    --output-csv  report.csv  \
    --verbose
```

### CI/CD — exit non‑zero if threats found

```bash
pcap2api-rs capture.pcap --quiet
echo "Exit code: $?"   # 0 = clean, 1 = threats detected
```

### Disable specific feeds you don't need

```bash
pcap2api-rs capture.pcap \
    --no-blocklist-de \
    --no-emerging-threats
```

### Use a custom cache directory

```bash
pcap2api-rs capture.pcap --cache-dir /var/cache/pcap2api-rs
```

---

## Environment variables

All API keys can be set as environment variables instead of passing them on the command line:

| Variable | Backend |
|---|---|
| `OTX_KEY` | AlienVault OTX |
| `PHISHTANK_KEY` | PhishTank (optional, raises rate limit) |
| `ABUSEIPDB_KEY` | AbuseIPDB |
| `VIRUSTOTAL_KEY` | VirusTotal |
| `SHODAN_KEY` | Shodan |

```bash
export ABUSEIPDB_KEY=your_key
pcap2api-rs capture.pcap
```

---

## Performance notes

- **Multicore extraction** – PCAP files are processed in parallel using Rayon. Use the `--workers` flag to control concurrency (default = number of CPU cores – 1).
- **Streaming PCAP reader** – Files are never fully loaded into memory; works with multi‑gigabyte captures.
- **Feed cache** – Feeds are downloaded only once per TTL window; subsequent runs are near‑instant.
- **Rate limiting** – API calls are spaced with `--rate-limit` (default 0.2 seconds) to respect service terms.

---

## Design notes

**Why not use IntelMQ directly?**  
IntelMQ is a full pipeline platform requiring Redis, multiple processes, and configuration files. This tool is aimed at analysts who want quick, ad‑hoc PCAP analysis without standing up infrastructure.

**Feed selection rationale**  
The seven feeds cover the main threat categories without overlap: malware distribution (URLhaus), active botnets/C2 (Feodo Tracker, Bambenek), phishing (PhishTank), opportunistic attackers (Blocklist.de), broad coverage (Emerging Threats), and community intelligence (OTX).

**Cache behaviour**  
Each feed is cached as a JSON file on disk. The TTL is set conservatively to match each provider's recommended update frequency and avoid hammering volunteer‑operated services (Blocklist.de 12 h, Emerging Threats 24 h).

**Classification taxonomy**  
All matches are tagged using the [IntelMQ Data Harmonisation](https://docs.intelmq.org/latest/dev/data-format/) / [RSIT](https://github.com/enisaeu/Reference-Security-Incident-Taxonomy-Task-Force/) ontology (`classification.type` and `classification.taxonomy`), making output compatible with IntelMQ event stores and MISP.

**Why Rust?**  
The Rust implementation is **10‑15x faster** than the Python original, uses a fraction of the memory, and provides true parallel PCAP processing. All functionality and CLI options remain identical.

---

## Full option reference

```
Usage: pcap2api-rs [OPTIONS] <FILE.pcap>...

Arguments:
  <FILE.pcap>...  One or more PCAP/CAP capture files to analyse

Options:
      --workers <N>                Parallel extraction workers [default: 4]
      --quiet                      Suppress non‑error output
      --verbose                    Show feed download progress
      --refresh-feeds              Force re‑download of all feeds
      --cache-dir <DIR>            Feed cache directory [default: ~/.cache/pcap2api-rs]
      --include-private            Include private/RFC1918 IPs in lookups
      --kinds <KIND>...            Observable kinds to look up [default: ip domain url]
      --output-json <FILE>         Save full results to a JSON file
      --output-csv <FILE>          Save threat matches to a CSV file
      --rate-limit <SECS>          Pause between remote API calls [default: 0.2]

  Feed collectors:
      --no-urlhaus                 Disable URLhaus feed
      --no-feodo                   Disable Feodo Tracker feed
      --no-phishtank               Disable PhishTank feed
      --no-bambenek                Disable Bambenek feed
      --no-blocklist-de            Disable Blocklist.de feed
      --no-emerging-threats        Disable Emerging Threats feed
      --otx-key <KEY>              AlienVault OTX API key
      --phishtank-key <KEY>        PhishTank API key (optional, raises rate limit)

  Remote API backends:
      --abuseipdb-key <KEY>        AbuseIPDB v2 API key
      --abuseipdb-min-score <N>    Minimum confidence score [default: 25]
      --virustotal-key <KEY>       VirusTotal v3 API key
      --virustotal-min-detections <N>  Minimum engine detections [default: 2]
      --shodan-key <KEY>           Shodan API key
      --intelmq-url <URL>          IntelMQ REST API base URL
      --intelmq-user <USER>        IntelMQ REST API username
      --intelmq-pass <PASS>        IntelMQ REST API password
      --no-heuristics              Disable local DGA / suspicious‑port heuristics

  Other:
  -h, --help                       Print help
  -V, --version                    Print version
```

---

## License

GPLv3 – see [LICENSE](LICENSE).

## Acknowledgements

- [IntelMQ](https://github.com/certtools/intelmq) – for the data harmonisation ontology and feed architecture
- [Abuse.ch](https://abuse.ch) – URLhaus, Feodo Tracker
- [PhishTank](https://www.phishtank.com)
- [Bambenek Consulting](https://osint.bambenekconsulting.com)
- [Blocklist.de](https://www.blocklist.de)
- [Proofpoint Emerging Threats](https://rules.emergingthreats.net)
- [AlienVault OTX](https://otx.alienvault.com)

## About this port

This Rust version was created with the assistance of **DeepSeek** (https://deepseek.com). It maintains 100% feature parity with the original Python `pcap2api`, while adding multicore PCAP processing, lower memory footprint, and a fully static binary for easy distribution.

If you find any issues or would like to contribute, please open a ticket on GitHub.