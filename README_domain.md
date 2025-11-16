domain.py — Subdomain Enumerator (Offline/Curation) (subenum)

Overview

- Purpose: A focused subdomain enumeration script that uses Certificate Transparency, DNS record analysis, and an offline curated wordlist to discover subdomains for a given domain.
- Location: `domain.py`

Requirements

- Python 3.8+
- Install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Quick Usage

```powershell
# Analyze a domain and save results (TXT by default)
python .\domain.py example.com -f txt,json,csv -o subdomain_results

# Quiet run, skip saving
python .\domain.py example.com -q --no-save
```

Features

- Certificate Transparency (crt.sh) lookup for historical certificate names.
- DNS records analysis (MX, NS, SOA, CNAME) to extract hostnames.
- Brute-force using a small curated offline list of common subdomain names.
- Concurrent DNS lookups for speed.
- Output formats: TXT, JSON, CSV saved to `subdomain_results/` by default.

Notes & Recommendations

- This script keeps a small curated offline list (no large local wordlist). Use `domain_advanced.py` if you prefer auto-fetching large online wordlists.
- Always scan only domains you own or have permission to test.
- For larger, deeper enumeration consider `domain_advanced.py` which supports online wordlists and port scanning.

License & Safety

- No license file is included; add one if you plan to publish the repository.
- Use responsibly and respect robots.txt and terms of service for target domains.
