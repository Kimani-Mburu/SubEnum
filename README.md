subenum — Subdomain Enumerator (simple + advanced)

This repository contains two Python scripts for subdomain enumeration:

- `domain.py` — focused, offline/curated-wordlist version (lighter, quicker)
- `domain_advanced.py` — advanced hybrid enumerator (CT + DNS + auto-fetch wordlists + TCP port scanning)

See the module READMEs for full details:

- `README_domain.md` — usage and notes for `domain.py`
- `README_domain_advanced.md` — usage, flags, and examples for `domain_advanced.py`

Quick start

1. Create and activate a virtual environment (Windows PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Examples

- Run the advanced hybrid script (default includes port scanning):

```powershell
python .\domain_advanced.py example.com -f txt,json,csv -o subdomain_results
```

- Run the lightweight offline script:

```powershell
python .\domain.py example.com -f txt
```

Files of interest

- `domain.py` — simpler enumerator that uses an offline curated subdomain list.
- `domain_advanced.py` — auto-fetches wordlists, queries Certificate Transparency (`crt.sh`), performs DNS record analysis, and optionally scans common TCP ports.
- `requirements.txt` — install runtime dependencies.
- `subdomain_results/` — (ignored by `.gitignore`) where output files are saved by default.

Security & Ethical Notice

- Only run these tools against domains you own or have permission to test.
- Port scanning can be intrusive. Use `--no-scan` to disable scanning and `--skip-wordlist` to skip large brute-force runs.

Contributing & Next Steps

- Add caching for downloaded wordlists to speed repeated runs.
- Add CI and unit tests for core functions.
- Consider adding a license file if you plan to publish the project.

If you want, I can also add a basic GitHub Actions workflow for linting or tests and mark this top-level README task completed in the todo list.
