#!/usr/bin/env python3
"""
domain.py — Lightweight subdomain enumerator (subenum)

Author: Michael Mburu
License: MIT

Description:
    Focuses on Certificate Transparency logs, DNS record analysis, and a curated
    offline subdomain wordlist for fast subdomain enumeration.
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
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Most common/useful subdomains (curated list)
COMMON_SUBDOMAINS = [
    # Standard web services
    "www", "mail", "ftp", "ns", "blog", "shop", "forum", "dev", "test", "admin",
    # API & cloud services
    "api", "api-v1", "api-v2", "cdn", "cms", "dashboard", "db",
    # Communication
    "email", "smtp", "pop", "pop3", "imap", "sms",
    # Development & staging
    "staging", "stage", "demo", "testing", "qa",
    # Infrastructure
    "dns", "ns1", "ns2", "ns3", "ns4", "vpn", "proxy",
    # Documentation & info
    "doc", "docs", "help", "wiki", "kb", "knowledge", "support",
    # Management
    "cpanel", "panel", "control", "manage", "management",
    # Development & CI/CD
    "git", "github", "gitlab", "jenkins", "ci", "cd",
    # Analytics & monitoring
    "analytics", "stats", "metrics", "monitor", "monitoring", "logs",
    # Portal & access
    "portal", "secure", "login", "auth", "oauth", "sso", "account",
    # File & storage
    "file", "files", "sftp", "storage", "backup",
    # Popular services
    "mail2", "webmail", "calendar", "contacts", "drive", "docs",
    "maps", "images", "search", "video", "photos", "photo",
    # Business
    "jobs", "careers", "sales", "marketing", "news", "press", "events",
    # Regional/language
    "en", "de", "fr", "es", "it", "nl", "ja", "zh", "ru",
    # Miscellaneous
    "app", "apps", "web", "mobile", "m", "wap", "live", "beta",
    "old", "legacy", "v1", "v2", "v3", "stg", "prod", "production",
    "server", "servers", "services", "service", "backend", "frontend",
    # Additional common ones
    "host", "hosting", "info", "name", "mail3", "mx", "autodiscover", "autoconfig"
]

def validate_domain(url_or_domain: str) -> str:
    """
    Validate and extract domain from URL or domain string.
    
    Args:
        url_or_domain: A URL or domain name
        
    Returns:
        str: Extracted domain name
        
    Raises:
        ValueError: If the domain is invalid
    """
    url_or_domain = url_or_domain.strip().lower()
    
    # Try to parse as URL first
    if "://" in url_or_domain:
        try:
            parsed = urlparse(url_or_domain)
            domain = parsed.netloc
        except Exception as e:
            logger.error(f"Failed to parse URL: {e}")
            raise ValueError(f"Invalid URL format: {url_or_domain}")
    else:
        domain = url_or_domain
    
    # Remove 'www.' prefix if present
    if domain.startswith("www."):
        domain = domain[4:]
    
    # Validate domain format
    domain_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    if not re.match(domain_pattern, domain):
        raise ValueError(f"Invalid domain format: {domain}")
    
    return domain

def check_subdomain(subdomain: str, domain: str) -> str | None:
    """
    Check if a subdomain exists for the given domain via DNS resolution.
    
    Args:
        subdomain: The subdomain to check
        domain: The main domain
        
    Returns:
        str: The subdomain if it exists, None otherwise
    """
    full_domain = f"{subdomain}.{domain}"
    try:
        dns.resolver.resolve(full_domain, 'A')
        logger.info(f"✓ [DNS] Found: {full_domain}")
        return subdomain
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.Timeout:
        logger.debug(f"⚠ [DNS] Timeout: {full_domain}")
        return None
    except Exception as e:
        logger.debug(f"[DNS] Error checking {full_domain}: {e}")
        return None

def get_certs_transparency_subdomains(domain: str) -> List[str]:
    """
    Query Certificate Transparency logs for subdomains using crt.sh API.
    
    Args:
        domain: The domain to query
        
    Returns:
        List[str]: List of subdomains found in CT logs
    """
    subdomains = set()
    try:
        logger.info(f"[CT] Querying Certificate Transparency logs for {domain}...")
        
        # Query crt.sh API
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            try:
                certs = response.json()
                for cert in certs:
                    # Extract subdomain from name_value field
                    names = cert.get('name_value', '').split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name.endswith(f".{domain}"):
                            # Extract just the subdomain part
                            subdomain = name[:-len(f".{domain}")]
                            if subdomain and not subdomain.startswith('*.'):
                                subdomains.add(subdomain)
                        elif name == domain:
                            # Root domain found
                            continue
                
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
    """
    Extract subdomains from DNS records (MX, NS, SOA, etc).
    
    Args:
        domain: The domain to query
        
    Returns:
        List[str]: List of subdomains found in DNS records
    """
    subdomains = set()
    record_types = ['MX', 'NS', 'SOA', 'CNAME']
    
    try:
        logger.info(f"[DNS Records] Analyzing DNS records for {domain}...")
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    record_str = str(rdata).lower()
                    
                    # Extract subdomains that belong to this domain
                    if domain in record_str:
                        # Find all domain-like patterns
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

def get_subdomains_dns_brute_force(domain: str, max_workers: int = 15) -> List[str]:
    """
    Find subdomains using DNS brute force with common wordlist.
    
    Args:
        domain: The domain to scan for subdomains
        max_workers: Maximum number of concurrent threads
        
    Returns:
        List[str]: List of found subdomains
    """
    found_subdomains = set()
    
    logger.info(f"[Brute Force] Starting DNS brute force with {len(COMMON_SUBDOMAINS)} common subdomains...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_subdomain, sub, domain): sub 
            for sub in COMMON_SUBDOMAINS
        }
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_subdomains.add(result)
    
    if found_subdomains:
        logger.info(f"[Brute Force] Found {len(found_subdomains)} subdomains via DNS brute force")
    
    return sorted(list(found_subdomains))

def get_subdomains_hybrid(domain: str) -> List[str]:
    """
    Hybrid approach combining multiple enumeration methods.
    
    Args:
        domain: The domain to scan
        
    Returns:
        List[str]: Combined list of unique subdomains
    """
    all_subdomains = set()
    
    print("\n" + "="*60)
    print(f"HYBRID SUBDOMAIN ENUMERATION FOR: {domain}")
    print("="*60)
    print("\nUsing 3 methods:")
    print("1. Certificate Transparency Logs (CT)")
    print("2. DNS Records Analysis (MX, NS, SOA)")
    print("3. Common Subdomain Brute Force (DNS)\n")
    
    # Method 1: Certificate Transparency
    ct_subs = set(get_certs_transparency_subdomains(domain))
    all_subdomains.update(ct_subs)
    
    # Method 2: DNS Records
    dns_recs_subs = set(get_dns_records_subdomains(domain))
    all_subdomains.update(dns_recs_subs)
    
    # Method 3: Brute Force
    brute_subs = set(get_subdomains_dns_brute_force(domain))
    all_subdomains.update(brute_subs)
    
    return sorted(list(all_subdomains))

def save_results(domain: str, subdomains: List[str]) -> str:
    """
    Save enumeration results to a text file.
    
    Args:
        domain: The domain that was scanned
        subdomains: List of found subdomains
        
    Returns:
        str: Path to the saved file
    """
    # kept for compatibility; not used directly by new CLI
    results_dir = "subdomain_results"
    os.makedirs(results_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(results_dir, f"{domain}_{timestamp}.txt")
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("="*70 + "\n")
        f.write("SUBDOMAIN ENUMERATION RESULTS\n")
        f.write("="*70 + "\n\n")
        f.write(f"Domain: {domain}\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Subdomains Found: {len(subdomains)}\n\n")
        f.write("SUBDOMAINS\n")
        f.write("="*70 + "\n")
        for i, subdomain in enumerate(subdomains, 1):
            f.write(f"{i}. {subdomain}.{domain}\n")
    return filename


def write_outputs(domain: str, subdomains: List[str], formats: List[str], out: str | None) -> List[str]:
    """Write results in requested formats. Returns list of written file paths."""
    results = []
    os.makedirs('subdomain_results', exist_ok=True)

    base_ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    # If out provided and looks like a file path, use it as base name
    if out:
        out = out.strip()
        # if it's a directory, use domain+timestamp inside it
        if os.path.isdir(out):
            base = os.path.join(out, f"{domain}_{base_ts}")
        else:
            # if extension present, strip for base
            base = out
            if any(base.lower().endswith(s) for s in ['.txt', '.json', '.csv']):
                base = os.path.splitext(base)[0]
    else:
        base = os.path.join('subdomain_results', f"{domain}_{base_ts}")

    if 'txt' in formats:
        path = base + '.txt'
        with open(path, 'w', encoding='utf-8') as f:
            f.write('='*70 + '\n')
            f.write(f'SUBDOMAIN ENUMERATION RESULTS\n')
            f.write('='*70 + '\n\n')
            f.write(f'Domain: {domain}\n')
            f.write(f'Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
            f.write(f'Total Subdomains Found: {len(subdomains)}\n\n')
            f.write('SUBDOMAINS\n')
            f.write('='*70 + '\n')
            for i, sub in enumerate(subdomains, 1):
                f.write(f'{i}. {sub}.{domain}\n')
        results.append(path)

    if 'json' in formats:
        path = base + '.json'
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'domain': domain, 'timestamp': datetime.now().isoformat(), 'count': len(subdomains), 'subdomains': [f'{s}.{domain}' for s in subdomains]}, f, indent=2)
        results.append(path)

    if 'csv' in formats:
        path = base + '.csv'
        with open(path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['index', 'subdomain'])
            for i, sub in enumerate(subdomains, 1):
                writer.writerow([i, f'{sub}.{domain}'])
        results.append(path)

    return results

def main():
    parser = argparse.ArgumentParser(description='Hybrid subdomain enumeration (CT + DNS records + common brute)')
    parser.add_argument('target', nargs='?', help='Domain or URL to analyze')
    parser.add_argument('-o', '--out', help='Output file path or directory (omit extension)')
    parser.add_argument('-f', '--formats', default='txt', help='Comma-separated output formats: txt,json,csv (default: txt)')
    parser.add_argument('--no-save', action='store_true', help='Do not save results to disk')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (errors only)')
    args = parser.parse_args()

    # configure logging level
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

        subdomains = get_subdomains_hybrid(domain)

        print('\n' + '='*60)
        print(f'RESULTS: Found {len(subdomains)} unique subdomain(s)')
        print('='*60 + '\n')

        for i, subdomain in enumerate(subdomains, 1):
            print(f'  {i}. {subdomain}.{domain}')

        print('\n' + '='*60 + '\n')

        formats = [s.strip().lower() for s in args.formats.split(',') if s.strip()]
        valid = {'txt', 'json', 'csv'}
        formats = [f for f in formats if f in valid]
        if not formats:
            formats = ['txt']

        written = []
        if not args.no_save:
            written = write_outputs(domain, subdomains, formats, args.out)
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
