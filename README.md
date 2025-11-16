# SubEnum — Hybrid Subdomain Enumerator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A fast, production-ready subdomain enumeration toolkit with two modes: a lightweight offline version and an advanced hybrid scanner with optional port enumeration and online wordlist fetching.

## 📋 Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Tools](#tools)
- [Examples](#examples)
- [Security & Ethics](#security--ethics)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

### Lightweight Mode (`domain.py`)
- **Certificate Transparency (CT)** lookups via crt.sh API
- **DNS records analysis** (MX, NS, SOA, CNAME)
- **Curated offline wordlist** brute-force (no external downloads)
- Concurrent DNS resolution for speed
- Multiple output formats (TXT, JSON, CSV)
- No external dependencies for wordlists

### Advanced Mode (`domain_advanced.py`)
- All features from lightweight mode, plus:
- **Auto-fetching online wordlists** from trusted sources (with caching)
- **TCP port scanning** on discovered subdomains (default: enabled)
- Configurable port ranges and scanning concurrency
- Custom wordlist URL support
- Advanced logging and progress reporting

## 🚀 Quick Start

### 1. Clone & Setup Environment

```powershell
# Clone the repository
git clone https://github.com/Kimani-Mburu/SubEnum.git
cd SubEnum

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Run a Scan

```powershell
# Lightweight fast scan (offline wordlist only)
python .\domain.py example.com

# Advanced scan with all features (includes port scanning)
python .\domain_advanced.py example.com --formats txt,json,csv
```

### 3. View Results

Results are saved in `subdomain_results/` by default with timestamps.

## 📦 Installation

### Requirements
- **Python 3.8** or higher
- Virtual environment (recommended)
- Internet connection (for CT lookups and advanced wordlist features)

### Steps

```powershell
# Clone repository
git clone https://github.com/Kimani-Mburu/SubEnum.git
cd SubEnum

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt

# (Optional) Install development dependencies for testing
pip install -r requirements-dev.txt
```

## 🎯 Usage

### Lightweight Mode: `domain.py`

Fast subdomain enumeration using offline wordlist, CT logs, and DNS records.

```powershell
python .\domain.py <domain> [options]
```

**Common options:**
- `-f, --formats txt,json,csv` — Output formats (default: txt)
- `-o, --out <path>` — Output directory or base filename
- `--no-save` — Don't save to disk
- `-v, --verbose` — Enable verbose logging
- `-q, --quiet` — Errors only

**Examples:**
```powershell
# Save in all formats
python .\domain.py example.com -f txt,json,csv

# Skip saving, verbose output
python .\domain.py example.com -v --no-save

# Custom output path
python .\domain.py example.com -o ./results/my_scan
```

See [README_domain.md](README_domain.md) for full documentation.

---

### Advanced Mode: `domain_advanced.py`

Comprehensive subdomain enumeration with online wordlists and port scanning.

```powershell
python .\domain_advanced.py <domain> [options]
```

**Key options:**
- `-w, --wordlist-url <url>` — Use custom online wordlist
- `--skip-wordlist` — Skip online wordlist (CT + DNS only)
- `--no-scan` — Disable TCP port scanning
- `-p, --ports <ports>` — Ports to scan (default: `80,443,8080,8443,22,21,25,3306,1433,3389,53`)
- `--scan-timeout <seconds>` — TCP timeout per port (default: 1.0)
- `--scan-workers <n>` — Max concurrent scan threads (default: 30)
- `-f, --formats txt,json,csv` — Output formats (default: txt)
- `-o, --out <path>` — Output directory or base filename
- `--no-save` — Don't save to disk
- `--refresh-wordlist` — Force refresh cached wordlists
- `-v, --verbose` — Enable verbose logging
- `-q, --quiet` — Errors only

**Examples:**
```powershell
# Full scan with all features
python .\domain_advanced.py example.com

# Fast scan (skip wordlist brute-force)
python .\domain_advanced.py example.com --skip-wordlist

# Scan specific ports only
python .\domain_advanced.py example.com -p 80,443,8080

# Custom wordlist and output
python .\domain_advanced.py example.com -w https://mywordlist.com/subdomains.txt -o ./results

# Quiet mode, save in JSON only
python .\domain_advanced.py example.com -f json -q
```

See [README_domain_advanced.md](README_domain_advanced.md) for full documentation.

---

## 🛠️ Tools

| File | Purpose | Mode |
|------|---------|------|
| `domain.py` | Lightweight subdomain enumerator | Fast, offline |
| `domain_advanced.py` | Advanced hybrid enumerator | Full-featured, with scanning |
| `requirements.txt` | Runtime dependencies | — |
| `requirements-dev.txt` | Development & test dependencies | Testing |
| `tests/test_core.py` | Unit tests | Testing |

## 📊 Example Outputs

### Text Output
```
============================================================
SUBDOMAIN ENUMERATION RESULTS
============================================================

Domain: example.com
Timestamp: 2025-11-16 13:06:00
Total Subdomains Found: 6

SUBDOMAINS
============================================================
1. www.example.com
2. mail.example.com
3. api.example.com
4. dev.example.com
5. cdn.example.com
6. support.example.com
```

### JSON Output
```json
{
  "domain": "example.com",
  "timestamp": "2025-11-16T13:06:00.000000",
  "count": 6,
  "subdomains": [
    {
      "subdomain": "www.example.com",
      "open_ports": [80, 443]
    }
  ]
}
```

### CSV Output
```csv
index,subdomain,open_ports
1,www.example.com,80;443
2,api.example.com,443
```

## 🔒 Security & Ethics

⚠️ **Important:** Use responsibly and legally.

### Prerequisites
- ✅ **Always obtain written permission** before scanning domains you don't own
- ✅ Test only on domains you have authorization to test
- ✅ Respect `robots.txt` and terms of service
- ✅ Be aware that port scanning can trigger security alerts

### Best Practices
- Use `--no-scan` if you only need enumeration without port scanning
- Use `--skip-wordlist` for faster, less intrusive scans
- Monitor rate limits when targeting production systems
- Review output before sharing or storing sensitive results
- Keep scan logs for audit purposes if required

### Limitations
- **Rate limiting:** Some services (crt.sh, DNS servers) may rate-limit requests
- **Accuracy:** DNS-based enumeration is passive and may miss internal/private subdomains
- **Coverage:** Wordlists may not include custom or non-standard subdomain names

## 🐛 Troubleshooting

### Issue: "No results found"
- **Check:** Is the domain active and configured?
- **Try:** Run with `-v` flag for verbose output
- **Try:** Verify DNS connectivity: `nslookup example.com`

### Issue: "Timeout errors"
- **Solution:** Increase `--scan-timeout` (e.g., `--scan-timeout 2.0`)
- **Solution:** Reduce `--scan-workers` (e.g., `--scan-workers 10`)

### Issue: "Permission denied" saving output
- **Solution:** Check write permissions on output directory
- **Solution:** Use `--no-save` to skip file writing and display results only

### Issue: "Module not found"
- **Solution:** Ensure virtual environment is activated: `.\.venv\Scripts\Activate.ps1`
- **Solution:** Reinstall dependencies: `pip install -r requirements.txt`

### Issue: Wordlist fails to download
- **Solution:** Verify internet connection
- **Solution:** Try `--refresh-wordlist` to force re-download
- **Solution:** Use `--skip-wordlist` to skip and rely on CT + DNS only

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```powershell
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest -v

# Run with coverage
pytest --cov
```

### Code Style
- Follow PEP 8
- Use type hints where practical
- Add docstrings to functions

## 📋 Roadmap

- [ ] Add support for SHODAN integration
- [ ] Implement result caching across runs
- [ ] Add HTTP/HTTPS banner grabbing
- [ ] Create Docker image for easy deployment
- [ ] Add GitHub Actions CI/CD workflow
- [ ] Implement rate-limiting awareness
- [ ] Add proxy support

## 📝 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Michael Mburu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 🙋 Support

For issues, questions, or suggestions:
- **GitHub Issues:** [Open an issue](https://github.com/Kimani-Mburu/SubEnum/issues)
- **Email:** Contact the maintainer

---

**Made with ❤️ by Michael Mburu**
