# domain.py — Lightweight Subdomain Enumerator

## Overview

**domain.py** is a fast, lightweight subdomain enumeration tool that focuses on efficiency and speed through offline data and curated wordlists. Perfect for quick reconnaissance without external dependencies.

### Key Characteristics
- ✅ **Offline operation** — no large wordlist downloads
- ✅ **Fast execution** — curated, common subdomains only
- ✅ **Low resource usage** — minimal dependencies
- ✅ **Production-ready** — concurrent DNS resolution
- 📍 **Location:** `domain.py`

---

## 📋 Requirements

- **Python 3.8+**
- Virtual environment (recommended)
- Internet connection (for Certificate Transparency and DNS lookups)

### Setup

```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Quick Start

### Basic Usage

```powershell
# Simplest form: scan domain and save to default location
python .\domain.py example.com

# Analyze and save in multiple formats
python .\domain.py example.com -f txt,json,csv

# Custom output location
python .\domain.py example.com -o ./my_results/scan1

# Verbose output (see all progress)
python .\domain.py example.com -v

# Quiet mode (errors only) without saving
python .\domain.py example.com -q --no-save
```

---

## 🛠️ Command-Line Options

```
Usage: python domain.py <domain> [options]

Positional Arguments:
  target                 Domain or URL to analyze (required, or will prompt)

Optional Arguments:
  -o, --out <path>       Output file path or directory (omit extension)
  -f, --formats <list>   Comma-separated formats: txt,json,csv (default: txt)
  --no-save              Do not save results to disk
  -v, --verbose          Enable verbose logging (debug level)
  -q, --quiet            Quiet mode - errors only
  -h, --help             Show this help message and exit
```

### Option Details

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | string | *interactive* | Domain or URL to analyze |
| `-o, --out` | path | `subdomain_results/` | Output directory or base filename |
| `-f, --formats` | csv list | `txt` | Output formats (`txt`, `json`, `csv`) |
| `--no-save` | flag | false | Disable writing results to disk |
| `-v, --verbose` | flag | false | Show debug-level logging |
| `-q, --quiet` | flag | false | Show only errors |

---

## ✨ Features Explained

### 1. Certificate Transparency Logs
Queries the **crt.sh** API to find all certificates issued for your domain and its subdomains. This reveals historical certificate names and thus previously used subdomains.

```
[CT] Querying Certificate Transparency logs for example.com...
[CT] Found 12 subdomains in Certificate Transparency logs
```

### 2. DNS Records Analysis
Analyzes MX, NS, SOA, and CNAME records for your domain to extract referenced hosts.

```
[DNS Records] Analyzing DNS records for example.com...
[DNS Records] Found 3 subdomains in DNS records
```

### 3. Curated Wordlist Brute-Force
Uses a built-in offline list of ~100 common subdomains (www, mail, api, cdn, etc.) to check for active hosts via DNS resolution.

```
[Brute Force] Starting DNS brute force with 100 common subdomains...
✓ [DNS] Found: www.example.com
✓ [DNS] Found: api.example.com
[Brute Force] Found 8 subdomains via DNS brute force
```

### 4. Concurrent DNS Resolution
Uses ThreadPoolExecutor to resolve multiple subdomains in parallel for maximum speed.

---

## 📊 Output Formats

### Text Format (Default)
```
============================================================
SUBDOMAIN ENUMERATION RESULTS
============================================================

Domain: example.com
Timestamp: 2025-11-16 13:06:00
Total Subdomains Found: 8

SUBDOMAINS
============================================================
1. www.example.com
2. api.example.com
3. mail.example.com
4. cdn.example.com
5. support.example.com
6. dev.example.com
7. ftp.example.com
8. admin.example.com
```

### JSON Format
```json
{
  "domain": "example.com",
  "timestamp": "2025-11-16T13:06:00.000000",
  "count": 8,
  "subdomains": [
    "www.example.com",
    "api.example.com",
    "mail.example.com"
  ]
}
```

### CSV Format
```csv
index,subdomain
1,www.example.com
2,api.example.com
3,mail.example.com
```

---

## 📝 Usage Examples

### Example 1: Quick Scan
```powershell
python .\domain.py google.com
```
**Result:** Scans google.com, displays results, saves to `subdomain_results/google.com_<timestamp>.txt`

---

### Example 2: All Output Formats
```powershell
python .\domain.py facebook.com -f txt,json,csv -v
```
**Result:** Creates three files (TXT, JSON, CSV) with verbose progress output

---

### Example 3: Custom Output Location
```powershell
python .\domain.py twitter.com -o ./scans/twitter_2025
```
**Result:** Saves to `./scans/twitter_2025.txt` (or .json, .csv if specified)

---

### Example 4: Interactive Mode
```powershell
python .\domain.py
```
**Input prompt:** `Enter the domain or URL to analyze: `

---

### Example 5: Silent Scan (Display Only)
```powershell
python .\domain.py linkedin.com --no-save -q
```
**Result:** Runs scan silently, no output files created

---

## 🎯 When to Use domain.py

**Use this tool when you need:**
- ✅ Fast, lightweight subdomain enumeration
- ✅ Quick security scans without external dependencies
- ✅ Offline operation (once installed)
- ✅ Minimal resource consumption
- ✅ Simple, predictable output

**Consider `domain_advanced.py` when you need:**
- 🔄 Larger wordlist coverage
- 🔍 Port scanning capabilities
- 🌐 Online wordlist fetching
- 📊 More detailed reconnaissance

---

## 🔒 Security Considerations

### Legal Requirements
- ✅ **Always obtain explicit permission** before scanning any domain
- ✅ Only test domains you own or are authorized to test
- ✅ Keep records of authorization for audit purposes

### DNS Best Practices
- Respects DNS server timeouts (default 10 seconds per query)
- Uses concurrent requests responsibly (configurable via code modification)
- Implements retry logic for transient failures

### Rate Limiting
- Certificate Transparency API: Generally permissive, but may rate-limit bulk queries
- Public DNS resolvers: Most support reasonable query rates for legitimate use
- Consider throttling if you frequently scan multiple domains

---

## 🐛 Troubleshooting

### No subdomains found
```
RESULTS: Found 0 unique subdomain(s)
```

**Solutions:**
1. Verify the domain name is correct: `nslookup example.com`
2. Run with verbose flag: `python .\domain.py example.com -v`
3. Check if the domain exists and has public DNS records
4. Some private/internal domains may not return results

---

### "No such host" errors
```
[DNS] Error checking www.example.com: NXDOMAIN
```

This is normal and expected. The tool attempts many combinations; not all will resolve.

---

### File permission errors
```
PermissionError: [Errno 13] Permission denied: 'subdomain_results/...'
```

**Solutions:**
1. Check write permissions on `subdomain_results/` directory
2. Use `--no-save` to skip file writing
3. Specify a different output directory: `-o C:\Temp\results`

---

### "Module not found" errors
```
ModuleNotFoundError: No module named 'dns'
```

**Solutions:**
1. Ensure virtual environment is activated: `.\.venv\Scripts\Activate.ps1`
2. Reinstall dependencies: `pip install -r requirements.txt`
3. Verify Python version: `python --version` (must be 3.8+)

---

## 💡 Tips & Best Practices

1. **Save historical results:** Include the default timestamp so results don't overwrite
   ```powershell
   python .\domain.py example.com
   ```
   Files include timestamp: `example.com_20251116_130525.txt`

2. **Use JSON for automation:** Parse JSON output for automated workflows
   ```powershell
   python .\domain.py example.com -f json --no-save
   ```

3. **Combine with other tools:** Use CSV format to import into spreadsheets
   ```powershell
   python .\domain.py example.com -f csv -o results
   ```

4. **Monitor progress:** Use `-v` flag for detailed logging
   ```powershell
   python .\domain.py example.com -v
   ```

---

## 📚 Related Documentation

- **Main README:** [README.md](README.md)
- **Advanced Tool:** [README_domain_advanced.md](README_domain_advanced.md)
- **Project Home:** [GitHub Repository](https://github.com/Kimani-Mburu/SubEnum)

---

## 📜 License & Legal

This tool is provided under the **MIT License**. See [LICENSE](LICENSE) for full details.

**Disclaimer:** This tool is for authorized security testing only. Unauthorized access to computer networks is illegal. Always obtain explicit written permission before testing any domain you don't own.
