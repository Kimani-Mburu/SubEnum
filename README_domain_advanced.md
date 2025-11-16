domain_advanced.py — Advanced Hybrid Subdomain Enumerator (subenum)

Overview

- Purpose: An advanced hybrid subdomain enumeration script that combines Certificate Transparency (crt.sh), DNS records analysis, and optional online wordlist brute-force with concurrent DNS checks and built-in TCP port scanning for discovered hosts.
- Location: `domain_advanced.py`

Requirements

- Python 3.8+
- Recommended: create a virtual environment and install requirements

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Quick Usage

```powershell
# Full hybrid run (CT + DNS + auto-fetch wordlist) — scanning is enabled by default
python .\domain_advanced.py example.com -f txt,json,csv -o subdomain_results

# Skip online wordlist loading (faster) and still run CT + DNS + port scanning
python .\domain_advanced.py example.com --skip-wordlist -f txt,json,csv

# Disable port scanning if you only want enumeration
python .\domain_advanced.py example.com --no-scan

# Provide a custom online wordlist URL
python .\domain_advanced.py example.com -w https://example.com/my-subdomains.txt

# Limit ports and adjust timeout/concurrency
python .\domain_advanced.py example.com -p 80,443,8080 -f txt,json --scan-timeout 0.8 --scan-workers 20
```

Key Flags

- `-w/--wordlist-url` : Use a custom online wordlist URL instead of default sources.
- `--skip-wordlist` : Skip wordlist brute-force (CT + DNS only).
- `--no-scan` : Disable TCP port scanning (scanning is enabled by default).
- `-p/--ports` : Comma-separated ports or ranges to scan (e.g. `1-1024,80,443`). Default: `80,443,8080,8443,22,21,25,3306,1433,3389,53`.
- `--scan-timeout` : Timeout (seconds) for each TCP connect attempt (default `1.0`).
- `--scan-workers` : Max concurrency for scanning operations (default `30`).
- `-f/--formats` : Output formats: `txt,json,csv` (default: `txt`).
- `-o/--out` : Output directory or base filename for saved results.
- `--no-save` : Do not write results to disk.
- `-v/--verbose` : Verbose logging; `-q/--quiet` for errors only.

Outputs

- By default results are saved in `subdomain_results/{domain}_{timestamp}.{ext}` for TXT, JSON and/or CSV.
- When port scanning is enabled the outputs include an `open_ports` column/field for each subdomain.

Security & Ethics

- Only scan domains you own or for which you have explicit permission to test.
- Port scanning can be intrusive; ensure you have authorization and avoid scanning production systems without permission.

Notes & Troubleshooting

- The script tries multiple trusted online wordlist sources and falls back if some are unreachable. You can force a specific source with `-w`.
- If you run many brute-force checks, network latency or rate limits may slow the run; adjust `--scan-workers` or use `--skip-wordlist` for quicker results.

Contact / Contribution

- This repository is set up for quick experimentation. If you want a more production-ready tool, consider adding:
  - Caching for downloaded wordlists
  - Better CT filtering (exclude internal-only hostnames, wildcard entries)
  - Unit tests and CI workflow

