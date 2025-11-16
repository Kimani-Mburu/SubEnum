#!/usr/bin/env python3
"""
domain_advanced.py — Advanced hybrid subdomain enumerator (subenum)

Author: Michael Mburu
License: MIT

Description:
    Combines Certificate Transparency logs, DNS record analysis, optional online
    wordlist brute-force, and concurrent TCP port scanning to enumerate subdomains
    for a target domain.
"""

import argparse
import csv
import dns.resolver
import json
import logging
import os
import re
import requests
from datetime import datetime
import hashlib
import time
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import socket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Built-in trusted wordlist sources (fallback order)
WORDLIST_SOURCES = [
    "https://wordlists-cdn.assetnote.io/data/commonspeak2/subdomains/subdomains.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    "https://raw.githubusercontent.com/pavanw3b/wordlist/master/subdomains.txt",
]

# Caching configuration for downloaded wordlists
DEFAULT_WORDLIST_CACHE_DIR = Path('.cache/wordlists')
DEFAULT_WORDLIST_TTL = 7 * 24 * 3600  # 7 days in seconds


def validate_domain(url_or_domain: str) -> str:
    """Validate and extract domain from URL or domain string."""
    url_or_domain = url_or_domain.strip().lower()
    
    if "://" in url_or_domain:
        try:
            parsed = urlparse(url_or_domain)
            domain = parsed.netloc
        except Exception as e:
            logger.error(f"Failed to parse URL: {e}")
            raise ValueError(f"Invalid URL format: {url_or_domain}")
    else:
        domain = url_or_domain
    
    if domain.startswith("www."):
        domain = domain[4:]
    
    domain_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    if not re.match(domain_pattern, domain):
        raise ValueError(f"Invalid domain format: {domain}")
    
    return domain


def check_subdomain(subdomain: str, domain: str) -> str | None:
    """Check if a subdomain exists via DNS resolution."""
    full_domain = f"{subdomain}.{domain}"
    try:
        dns.resolver.resolve(full_domain, 'A')
        logger.info(f"✓ [DNS] Found: {full_domain}")
        return subdomain
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return None
    except Exception as e:
        logger.debug(f"[DNS] Error checking {full_domain}: {e}")
        return None


def get_certs_transparency_subdomains(domain: str) -> List[str]:
    """Query Certificate Transparency logs for subdomains."""
    subdomains = set()
    try:
        logger.info(f"[CT] Querying Certificate Transparency logs for {domain}...")
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            try:
                certs = response.json()
                for cert in certs:
                    names = cert.get('name_value', '').split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name.endswith(f".{domain}"):
                            subdomain = name[:-len(f".{domain}")]
                            if subdomain and not subdomain.startswith('*.'):
                                subdomains.add(subdomain)
                
                if subdomains:
                    logger.info(f"[CT] Found {len(subdomains)} subdomains in Certificate Transparency logs")
            except:
                pass
    except requests.RequestException as e:
        logger.warning(f"[CT] Failed to query Certificate Transparency: {e}")
    except Exception as e:
        logger.debug(f"[CT] Error: {e}")
    
    return list(subdomains)


def get_dns_records_subdomains(domain: str) -> List[str]:
    """Extract subdomains from DNS records (MX, NS, SOA, CNAME)."""
    subdomains = set()
    record_types = ['MX', 'NS', 'SOA', 'CNAME']
    
    try:
        logger.info(f"[DNS Records] Analyzing DNS records for {domain}...")
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    record_str = str(rdata).lower()
                    if domain in record_str:
                        pattern = r'([a-z0-9-]+\.' + re.escape(domain) + r')'
                        matches = re.findall(pattern, record_str)
                        for match in matches:
                            subdomain = match[:-len(f".{domain}")]
                            if subdomain and not subdomain.startswith('*.'):
                                subdomains.add(subdomain)
                                logger.debug(f"[DNS Records] Found {match} in {record_type} record")
            except:
                pass
    except Exception as e:
        logger.debug(f"[DNS Records] Error: {e}")
    
    if subdomains:
        logger.info(f"[DNS Records] Found {len(subdomains)} subdomains in DNS records")
    
    return list(subdomains)


def get_online_wordlist(url: str) -> List[str]:
    """Fetch subdomain wordlist from online source.

    Uses a local cache (under `.cache/wordlists`) to avoid repeated downloads. This function
    will return cached content when available and not expired unless `refresh` is True.
    """
    return _fetch_wordlist_with_cache(url)


def _cache_path_for_url(url: str, cache_dir: Path = DEFAULT_WORDLIST_CACHE_DIR) -> Path:
    h = hashlib.sha256(url.encode('utf-8')).hexdigest()
    return cache_dir / f"{h}.txt"


def _fetch_wordlist_with_cache(url: str, cache_dir: Path = DEFAULT_WORDLIST_CACHE_DIR, ttl: int = DEFAULT_WORDLIST_TTL, refresh: bool = False) -> List[str]:
    """Fetch the wordlist and cache it locally. Returns list of strings.

    If a cached file exists and is younger than `ttl` seconds and `refresh` is False,
    the cached file is used.
    """
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path = _cache_path_for_url(url, cache_dir)

        if cache_path.exists() and not refresh:
            mtime = cache_path.stat().st_mtime
            age = time.time() - mtime
            if age <= ttl:
                try:
                    text = cache_path.read_text(encoding='utf-8')
                    wordlist = [line.strip().lower() for line in text.split('\n') if line.strip()]
                    logger.info(f"[Wordlist][Cache] Loaded {len(wordlist)} entries from cache for {url}")
                    return wordlist
                except Exception:
                    # Fall through to re-download
                    pass

        logger.info(f"[Wordlist] Fetching online wordlist from {url}...")
        response = requests.get(url, timeout=15)
        if response.status_code == 200 and response.text:
            text = response.text
            try:
                cache_path.write_text(text, encoding='utf-8')
            except Exception:
                logger.debug(f"[Wordlist] Failed to write cache to {cache_path}")
            wordlist = [line.strip().lower() for line in text.split('\n') if line.strip()]
            logger.info(f"[Wordlist] Fetched {len(wordlist)} subdomains from online source")
            return wordlist
    except Exception as e:
        logger.debug(f"[Wordlist] Failed to fetch from {url}: {e}")
    return []


def get_default_wordlist() -> List[str]:
    """Try to fetch from multiple trusted sources until one succeeds."""
    logger.info("[Wordlist] Fetching default wordlist from trusted sources...")
    for url in WORDLIST_SOURCES:
        wordlist = get_online_wordlist(url)
        if wordlist:
            return wordlist
    logger.warning("[Wordlist] Failed to fetch from all default sources")
    return []


def brute_force_with_wordlist(domain: str, wordlist: List[str], max_workers: int = 15) -> List[str]:
    """Brute force subdomains using provided wordlist."""
    if not wordlist:
        logger.warning("[Brute Force] No wordlist provided, skipping")
        return []
    
    found_subdomains = set()
    logger.info(f"[Brute Force] Starting DNS brute force with {len(wordlist)} subdomains...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_subdomain, sub, domain): sub 
            for sub in wordlist
        }
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_subdomains.add(result)
    
    if found_subdomains:
        logger.info(f"[Brute Force] Found {len(found_subdomains)} subdomains via brute force")
    
    return sorted(list(found_subdomains))


def parse_ports_arg(ports_arg: str) -> List[int]:
    """Parse a ports argument which may include commas and ranges (e.g. '80,443,1-1024')."""
    ports = set()
    for part in str(ports_arg).split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                a, b = part.split('-', 1)
                a, b = int(a), int(b)
                if a <= 0 or b <= 0 or b < a:
                    continue
                for p in range(a, b + 1):
                    ports.add(p)
            except Exception:
                continue
        else:
            try:
                ports.add(int(part))
            except Exception:
                continue
    return sorted([p for p in ports if 0 < p <= 65535])


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if TCP connect to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_ports_for_host(host: str, ports: List[int], timeout: float = 1.0, max_workers: int = 30) -> List[int]:
    """Scan multiple ports on a single host concurrently and return a sorted list of open ports."""
    open_ports: List[int] = []
    if not ports:
        return open_ports

    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as executor:
        futures = {executor.submit(is_port_open, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            p = futures[future]
            try:
                if future.result():
                    open_ports.append(p)
            except Exception:
                continue

    return sorted(open_ports)


def scan_subdomains_ports(subdomains: List[str], domain: str, ports: List[int], timeout: float = 1.0, max_workers: int = 30) -> Dict[str, List[int]]:
    """Scan `ports` for each subdomain. Returns mapping subdomain -> open ports list.

    Subdomains should be labels (without the main domain). The function attempts to resolve
    the subdomain to an IP first; if not resolvable, it will attempt scanning the hostname itself.
    """
    results: Dict[str, List[int]] = {}
    if not subdomains:
        return results

    # First resolve subdomains (A records) in parallel
    def resolve_host(s: str) -> Optional[str]:
        fqdn = f"{s}.{domain}"
        try:
            ans = dns.resolver.resolve(fqdn, 'A')
            for r in ans:
                ip = str(r)
                if ip:
                    return ip
        except Exception:
            return None
        return None

    resolved: Dict[str, Optional[str]] = {}
    with ThreadPoolExecutor(max_workers=min(30, max(4, len(subdomains)))) as executor:
        future_to_sub = {executor.submit(resolve_host, s): s for s in subdomains}
        for fut in as_completed(future_to_sub):
            s = future_to_sub[fut]
            try:
                resolved[s] = fut.result()
            except Exception:
                resolved[s] = None

    # Now scan ports for each resolved IP or hostname
    with ThreadPoolExecutor(max_workers=min(30, max(4, len(subdomains)))) as executor:
        futures = {}
        for s in subdomains:
            target = resolved.get(s) or f"{s}.{domain}"
            futures[executor.submit(scan_ports_for_host, target, ports, timeout, max_workers)] = s

        for fut in as_completed(futures):
            s = futures[fut]
            try:
                results[s] = fut.result()
            except Exception:
                results[s] = []

    return results


def write_outputs(domain: str, subdomains: List[str], formats: List[str], out: str | None, port_map: Optional[Dict[str, List[int]]] = None) -> List[str]:
    """Write results in requested formats.

    `subdomains` is a list of subdomain labels (without the main domain). `port_map` is an optional
    mapping from subdomain label -> list of open ports.
    """
    results = []
    os.makedirs('subdomain_results', exist_ok=True)

    base_ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    if out:
        out = out.strip()
        if os.path.isdir(out):
            base = os.path.join(out, f"{domain}_{base_ts}")
        else:
            base = out
            if any(base.lower().endswith(s) for s in ['.txt', '.json', '.csv']):
                base = os.path.splitext(base)[0]
    else:
        base = os.path.join('subdomain_results', f"{domain}_{base_ts}")

    if 'txt' in formats:
        path = base + '.txt'
        with open(path, 'w', encoding='utf-8') as f:
            f.write('='*70 + '\n')
            f.write(f'SUBDOMAIN ENUMERATION RESULTS (Advanced - No Hardcoded Wordlist)\n')
            f.write('='*70 + '\n\n')
            f.write(f'Domain: {domain}\n')
            f.write(f'Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
            f.write(f'Total Subdomains Found: {len(subdomains)}\n\n')
            f.write('SUBDOMAINS\n')
            f.write('='*70 + '\n')
            for i, sub in enumerate(subdomains, 1):
                ports = port_map.get(sub, []) if port_map else []
                ports_str = f' - open ports: {",".join(str(p) for p in ports)}' if ports else ''
                f.write(f'{i}. {sub}.{domain}{ports_str}\n')
        results.append(path)

    if 'json' in formats:
        path = base + '.json'
        payload = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'count': len(subdomains),
        }
        if port_map:
            payload['subdomains'] = [{'subdomain': f'{s}.{domain}', 'open_ports': port_map.get(s, [])} for s in subdomains]
        else:
            payload['subdomains'] = [f'{s}.{domain}' for s in subdomains]

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
        results.append(path)

    if 'csv' in formats:
        path = base + '.csv'
        with open(path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            if port_map:
                writer.writerow(['index', 'subdomain', 'open_ports'])
                for i, sub in enumerate(subdomains, 1):
                    ports = ';'.join(str(p) for p in (port_map.get(sub, []) or []))
                    writer.writerow([i, f'{sub}.{domain}', ports])
            else:
                writer.writerow(['index', 'subdomain'])
                for i, sub in enumerate(subdomains, 1):
                    writer.writerow([i, f'{sub}.{domain}'])
        results.append(path)

    return results


def main():
    parser = argparse.ArgumentParser(description='Advanced hybrid subdomain enumeration (CT + DNS + auto-fetch wordlist)')
    parser.add_argument('target', nargs='?', help='Domain or URL to analyze')
    parser.add_argument('-o', '--out', help='Output file path or directory (omit extension)')
    parser.add_argument('-f', '--formats', default='txt', help='Comma-separated output formats: txt,json,csv (default: txt)')
    parser.add_argument('-w', '--wordlist-url', help='URL to custom subdomain wordlist (overrides default)')
    parser.add_argument('--skip-wordlist', action='store_true', help='Skip wordlist brute force (CT + DNS only)')
    parser.add_argument('--refresh-wordlist', action='store_true', help='Force refresh of cached wordlists (ignore cache)')
    parser.add_argument('--no-save', action='store_true', help='Do not save results to disk')
    parser.add_argument('--no-scan', action='store_true', help='Disable TCP port scan for discovered subdomains (scan is enabled by default)')
    parser.add_argument('-p', '--ports', default='80,443,8080,8443,22,21,25,3306,1433,3389,53', help='Comma-separated ports or ranges to scan (e.g. 1-1024,80,443)')
    parser.add_argument('--scan-timeout', type=float, default=1.0, help='Timeout seconds for each port connection attempt (default: 1.0)')
    parser.add_argument('--scan-workers', type=int, default=30, help='Max concurrency for port scanning operations')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (errors only)')
    args = parser.parse_args()

    # Configure logging level
    if args.quiet:
        logger.setLevel(logging.ERROR)
    elif args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    try:
        if args.target:
            user_input = args.target
        else:
            user_input = input('\nEnter the domain or URL to analyze: ').strip()

        if not user_input:
            logger.error('No input provided.')
            return

        domain = validate_domain(user_input)
        logger.info(f'Validated domain: {domain}\n')

        all_subdomains = set()

        print('\n' + '='*60)
        print(f'ADVANCED HYBRID SUBDOMAIN ENUMERATION FOR: {domain}')
        print('='*60)
        print('\nUsing methods:')
        print('1. Certificate Transparency Logs (CT)')
        print('2. DNS Records Analysis (MX, NS, SOA, CNAME)')
        if not args.skip_wordlist:
            print('3. Online Wordlist Brute Force (DNS)')
        print()

        # Method 1: Certificate Transparency
        ct_subs = set(get_certs_transparency_subdomains(domain))
        all_subdomains.update(ct_subs)

        # Method 2: DNS Records
        dns_recs_subs = set(get_dns_records_subdomains(domain))
        all_subdomains.update(dns_recs_subs)

        # Method 3: Online Wordlist (default or custom)
        if not args.skip_wordlist:
            if args.wordlist_url:
                wordlist = _fetch_wordlist_with_cache(args.wordlist_url, refresh=args.refresh_wordlist)
            else:
                # try default sources and honor refresh flag
                logger.info("[Wordlist] Fetching default wordlist from trusted sources...")
                wordlist = []
                for url in WORDLIST_SOURCES:
                    wordlist = _fetch_wordlist_with_cache(url, refresh=args.refresh_wordlist)
                    if wordlist:
                        break
            
            if wordlist:
                brute_subs = set(brute_force_with_wordlist(domain, wordlist))
                all_subdomains.update(brute_subs)

        subdomains = sorted(list(all_subdomains))

        port_results: Optional[Dict[str, List[int]]] = None
        scan_enabled = not args.no_scan
        if scan_enabled:
            ports_to_scan = parse_ports_arg(args.ports)
            if not ports_to_scan:
                logger.warning('No valid ports to scan were provided; skipping scan')
            else:
                logger.info(f"Scanning {len(ports_to_scan)} port(s) on {len(subdomains)} subdomain(s)...")
                print('\n' + '='*60)
                print(f'PORT SCAN: Scanning {len(ports_to_scan)} port(s) on {len(subdomains)} subdomain(s) (enabled by default)')
                print('='*60 + '\n')
                port_results = scan_subdomains_ports(subdomains, domain, ports_to_scan, timeout=args.scan_timeout, max_workers=args.scan_workers)

        print('\n' + '='*60)
        print(f'RESULTS: Found {len(subdomains)} unique subdomain(s)')
        print('='*60 + '\n')

        for i, subdomain in enumerate(subdomains, 1):
            ports_display = ''
            if port_results and subdomain in port_results and port_results[subdomain]:
                ports_display = ' [open ports: ' + ','.join(str(p) for p in port_results[subdomain]) + ']'
            print(f'  {i}. {subdomain}.{domain}{ports_display}')

        print('\n' + '='*60 + '\n')

        formats = [s.strip().lower() for s in args.formats.split(',') if s.strip()]
        valid = {'txt', 'json', 'csv'}
        formats = [f for f in formats if f in valid]
        if not formats:
            formats = ['txt']

        if not args.no_save:
            written = write_outputs(domain, subdomains, formats, args.out, port_map=port_results)
            for p in written:
                print(f'Saved: {p}')
        else:
            logger.info('Skipping save (--no-save)')

    except ValueError as e:
        logger.error(f'Invalid input: {e}')
    except KeyboardInterrupt:
        logger.info('\nOperation cancelled by user.')
    except Exception as e:
        logger.error(f'An unexpected error occurred: {e}')


if __name__ == "__main__":
    main()
