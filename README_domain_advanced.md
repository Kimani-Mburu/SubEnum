# domain_advanced.py — Advanced Hybrid Subdomain Enumerator

## Overview

**domain_advanced.py** is a comprehensive subdomain enumeration tool that combines multiple reconnaissance techniques with optional TCP port scanning. It auto-fetches online wordlists, implements intelligent caching, and provides detailed reconnaissance reports.

### Key Characteristics
- 🚀 **Full-featured** — CT + DNS + online wordlists + port scanning
- 💾 **Smart caching** — cache wordlists locally to avoid repeated downloads
- 🔍 **Port scanning** — discover open ports on found subdomains (default: enabled)
- 🌐 **Online wordlists** — fetch from multiple trusted sources
- 📊 **Detailed reporting** — includes port information in outputs
- 📍 **Location:** `domain_advanced.py`

---

## 📋 Requirements

- **Python 3.8+**
- Virtual environment (recommended)
- Internet connection (for CT, DNS, and wordlist fetching)

### Setup

```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# (Optional) Install dev/test dependencies
pip install -r requirements-dev.txt
```

---

## 🚀 Quick Start

### Basic Usage

```powershell
# Full scan: CT + DNS + wordlist brute-force + port scanning (default)
python .\domain_advanced.py example.com

# Fast enumeration: skip wordlist but keep port scanning
python .\domain_advanced.py example.com --skip-wordlist

# Enumeration only: no port scanning
python .\domain_advanced.py example.com --no-scan

# Multiple output formats
python .\domain_advanced.py example.com -f txt,json,csv

# Custom wordlist and limited ports
python .\domain_advanced.py example.com -w https://mywordlist.com/subdomains.txt -p 80,443

# Quiet mode with JSON output only
python .\domain_advanced.py example.com -f json -q
```

---

## 🛠️ Command-Line Options

```
Usage: python domain_advanced.py <domain> [options]

Positional Arguments:
  target                      Domain or URL to analyze (required, or will prompt)

Enumeration Options:
  -w, --wordlist-url <url>    Use custom online wordlist (overrides defaults)
  --skip-wordlist             Skip wordlist brute-force (CT + DNS only)
  --refresh-wordlist          Force refresh cached wordlists

Port Scanning Options:
  --no-scan                   Disable port scanning (enabled by default)
  -p, --ports <list>          Ports/ranges to scan (default: 80,443,8080,8443,...)
  --scan-timeout <seconds>    Timeout per port connection (default: 1.0)
  --scan-workers <n>          Max concurrent scan threads (default: 30)

Output Options:
  -o, --out <path>            Output directory or base filename
  -f, --formats <list>        Output formats: txt,json,csv (default: txt)
  --no-save                   Do not save results to disk

Logging Options:
  -v, --verbose               Enable verbose logging (debug level)
  -q, --quiet                 Quiet mode - errors only
  -h, --help                  Show this help message and exit
```

### Comprehensive Option Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | string | *interactive* | Domain or URL to analyze |
| `-w, --wordlist-url` | URL | defaults | Use custom online wordlist |
| `--skip-wordlist` | flag | false | Skip wordlist brute-force |
| `--refresh-wordlist` | flag | false | Force re-download cached wordlists |
| `--no-scan` | flag | false | Disable port scanning |
| `-p, --ports` | csv/range | 80,443,... | Ports to scan (e.g., `1-1024,80,443`) |
| `--scan-timeout` | float | 1.0 | Timeout seconds per port |
| `--scan-workers` | int | 30 | Max concurrent scanning threads |
| `-o, --out` | path | `subdomain_results/` | Output directory or filename |
| `-f, --formats` | csv list | `txt` | Output formats (txt, json, csv) |
| `--no-save` | flag | false | Skip writing files |
| `-v, --verbose` | flag | false | Show debug-level logging |
| `-q, --quiet` | flag | false | Show errors only |

---

## ✨ Features Explained

### 1. Certificate Transparency Logs
Queries **crt.sh** API to find all certificates issued for the domain. Reveals historically used and currently active subdomains.

```
[CT] Querying Certificate Transparency logs for example.com...
[CT] Found 25 subdomains in Certificate Transparency logs
```

### 2. DNS Records Analysis
Extracts hostnames from MX, NS, SOA, and CNAME records pointing to your domain infrastructure.

```
[DNS Records] Analyzing DNS records for example.com...
[DNS Records] Found 5 subdomains in DNS records
```

### 3. Online Wordlist Brute-Force
Automatically fetches subdomain wordlists from trusted sources (with local caching) and performs DNS resolution for each.

**Default wordlist sources:**
1. `https://wordlists-cdn.assetnote.io/data/commonspeak2/subdomains/subdomains.txt`
2. `https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt`
3. `https://raw.githubusercontent.com/pavanw3b/wordlist/master/subdomains.txt`

```
[Wordlist] Fetching default wordlist from trusted sources...
[Wordlist] Fetched 5000 subdomains from online source
[Brute Force] Starting DNS brute force with 5000 subdomains...
[Brute Force] Found 47 subdomains via brute force
```

**Cache behavior:**
- Wordlists are cached in `.cache/wordlists/` (SHA256 hash of URL)
- Cache expiration: 7 days by default
- Use `--refresh-wordlist` to force re-download

### 4. Concurrent DNS Resolution
Uses ThreadPoolExecutor for fast, parallel DNS lookups across all enumeration methods.

### 5. TCP Port Scanning
Discovers open ports on found subdomains with configurable:
- **Port list:** customize ports to scan
- **Timeout:** adjust connection timeout
- **Concurrency:** control thread pool size

```
PORT SCAN: Scanning 10 port(s) on 47 subdomain(s)
[Open Port] api.example.com:443
[Open Port] www.example.com:80
```

---

## 📊 Output Formats

### Text Format (Default)
```
============================================================
SUBDOMAIN ENUMERATION RESULTS (Advanced - No Hardcoded Wordlist)
============================================================

Domain: example.com
Timestamp: 2025-11-16 13:06:00
Total Subdomains Found: 47

SUBDOMAINS
============================================================
1. www.example.com - open ports: 80,443
2. api.example.com - open ports: 443
3. mail.example.com - open ports: 25,587,993
4. cdn.example.com - open ports: 80,443
...
```

### JSON Format
```json
{
  "domain": "example.com",
  "timestamp": "2025-11-16T13:06:00.000000",
  "count": 47,
  "subdomains": [
    {
      "subdomain": "www.example.com",
      "open_ports": [80, 443]
    },
    {
      "subdomain": "api.example.com",
      "open_ports": [443]
    }
  ]
}
```

### CSV Format
```csv
index,subdomain,open_ports
1,www.example.com,80;443
2,api.example.com,443
3,mail.example.com,25;587;993
```

---

## 📝 Usage Examples

### Example 1: Complete Reconnaissance
```powershell
python .\domain_advanced.py example.com -f txt,json,csv -v
```
**Result:** Full scan with CT + DNS + wordlist + port scanning, verbose output, all formats

---

### Example 2: Fast Enumeration (No Port Scanning)
```powershell
python .\domain_advanced.py example.com --no-scan
```
**Result:** CT + DNS + wordlist brute-force, no port scanning (faster)

---

### Example 3: Quick Scan (Skip Wordlist)
```powershell
python .\domain_advanced.py example.com --skip-wordlist
```
**Result:** CT + DNS + port scanning only (minimal brute-force)

---

### Example 4: Custom Wordlist
```powershell
python .\domain_advanced.py example.com -w https://mywordlist.com/subdomains.txt
```
**Result:** Use custom wordlist instead of defaults

---

### Example 5: Limited Port Scanning
```powershell
python .\domain_advanced.py example.com -p 80,443,8080,8443,22
```
**Result:** Scan only specified ports (faster)

---

### Example 6: Port Range Scanning
```powershell
python .\domain_advanced.py example.com -p 1-1024,8000-9000
```
**Result:** Scan port ranges (1-1024 and 8000-9000)

---

### Example 7: Aggressive Scan with Custom Timeout
```powershell
python .\domain_advanced.py example.com -p 1-65535 --scan-timeout 0.5 --scan-workers 50
```
**Result:** Full port range scan with aggressive settings (may be slow)

---

### Example 8: Silent Operation
```powershell
python .\domain_advanced.py example.com -q --no-save
```
**Result:** Runs silently, outputs results to console only

---

### Example 9: Force Refresh Wordlist Cache
```powershell
python .\domain_advanced.py example.com --refresh-wordlist
```
**Result:** Downloads fresh wordlist even if cached version exists

---

### Example 10: JSON Output for Automation
```powershell
python .\domain_advanced.py example.com -f json -o results/scan --no-save
```
**Result:** Outputs JSON results to console for parsing in automation

---

## 🎯 When to Use domain_advanced.py

**Use this tool when you need:**
- ✅ Comprehensive subdomain reconnaissance
- ✅ Port discovery on found subdomains
- ✅ Large wordlist coverage
- ✅ Detailed vulnerability scanning data
- ✅ Automated security assessments

**Consider `domain.py` when you need:**
- 🏃 Fast, lightweight scans
- 📍 Offline operation
- 🎯 Minimal resource usage

---

## 🔒 Security & Legal Considerations

### Authorization Requirements
- ✅ **Obtain written permission** before testing any domain
- ✅ Only scan domains you own or are authorized to test
- ✅ Port scanning is intrusive; ensure authorization
- ✅ Respect rate limits and server resources
- ✅ Keep records for audit purposes

### Best Practices

1. **Limit scope when testing production systems:**
   ```powershell
   # Conservative scan: limited ports, higher timeout
   python .\domain_advanced.py example.com -p 80,443 --scan-timeout 2.0
   ```

2. **Use appropriate timeouts:**
   ```powershell
   # Slower networks
   python .\domain_advanced.py example.com --scan-timeout 3.0
   
   # Fast networks
   python .\domain_advanced.py example.com --scan-timeout 0.5
   ```

3. **Control concurrency for target stability:**
   ```powershell
   # Conservative (fewer threads)
   python .\domain_advanced.py example.com --scan-workers 10
   
   # Aggressive (more threads)
   python .\domain_advanced.py example.com --scan-workers 50
   ```

4. **Skip wordlist for sensitive environments:**
   ```powershell
   python .\domain_advanced.py example.com --skip-wordlist
   ```

### Rate Limiting

- **Certificate Transparency:** Generally allows queries; may rate-limit bulk requests
- **DNS resolvers:** Public resolvers typically support reasonable query rates
- **Online wordlists:** May be rate-limited; `--refresh-wordlist` respects caching
- **Target system:** Port scanning can generate security alerts

---

## 🐛 Troubleshooting

### Issue: Few or no subdomains found
```
RESULTS: Found 0 unique subdomain(s)
```

**Solutions:**
1. Verify domain: `nslookup example.com`
2. Enable verbose logging: `-v`
3. Check CT doesn't have certificates: Visit `https://crt.sh/?q=%.example.com`
4. Try `--refresh-wordlist` to update wordlist

---

### Issue: Wordlist download fails
```
[Wordlist] Failed to fetch from https://...
```

**Solutions:**
1. Check internet connection
2. Try `--refresh-wordlist` to force re-download
3. Use `--skip-wordlist` to continue without wordlist
4. Provide custom wordlist: `-w <url>`

---

### Issue: Port scan is slow
```
Scanning 65535 port(s) on 100 subdomain(s)...
```

**Solutions:**
1. Reduce port range: `-p 80,443,8080`
2. Increase timeout (reduce retries): `--scan-timeout 0.5`
3. Increase workers: `--scan-workers 50`
4. Use `--no-scan` to skip scanning

---

### Issue: "Connection timeout" errors
```
[Scan] Timeout scanning api.example.com:443
```

**Solutions:**
1. Increase timeout: `--scan-timeout 2.0`
2. Reduce workers: `--scan-workers 15`
3. Reduce port list: `-p 80,443`

---

### Issue: Cache not updating
```
[Wordlist][Cache] Loaded X entries from cache
```

**Solutions:**
1. Force refresh: `--refresh-wordlist`
2. Clear cache: `rmdir .cache\wordlists /s`

---

## 💡 Tips & Tricks

### 1. **Two-stage scanning**
First check what's available, then detailed port scan:
```powershell
# Stage 1: Quick enumeration
python .\domain_advanced.py example.com --skip-wordlist --no-scan -q -o results/stage1

# Stage 2: Detailed port scan
python .\domain_advanced.py example.com --skip-wordlist -p 1-1024,3000-3999,8000-9000 -o results/stage2
```

### 2. **Export for further analysis**
```powershell
# JSON for parsing
python .\domain_advanced.py example.com -f json -o results/report

# CSV for spreadsheet analysis
python .\domain_advanced.py example.com -f csv -o results/report
```

### 3. **Monitor network impact**
```powershell
# Low-impact scan
python .\domain_advanced.py example.com -p 80,443 --skip-wordlist --scan-workers 5 --scan-timeout 2.0 -v
```

### 4. **Parallel scans** (outside script)
```powershell
# Run multiple domains in parallel (PowerShell)
@("example.com", "google.com", "facebook.com") | ForEach-Object -Parallel {
    python .\domain_advanced.py $_ -q --no-save
} -ThrottleLimit 3
```

---

## 📚 Related Documentation

- **Main README:** [README.md](README.md)
- **Lightweight Tool:** [README_domain.md](README_domain.md)
- **Project Home:** [GitHub Repository](https://github.com/Kimani-Mburu/SubEnum)

---

## 📜 License & Legal

This tool is provided under the **MIT License**. See [LICENSE](LICENSE) for full details.

**Disclaimer:** This tool is for authorized security testing only. Port scanning and DNS enumeration of systems without explicit permission may be illegal. Always obtain written authorization before testing any system you don't own.

