# scanner/subdomain.py
import requests
import tldextract
import dns.resolver
from urllib.parse import urlparse

CRTSH_JSON = "https://crt.sh/?q=%25{domain}&output=json"

COMMON_PREFIXES = ["www", "dev", "test", "stage", "staging", "api", "beta", "m", "mobile"]

def crtsh_subdomains(domain):
    """Query crt.sh for subdomains (best-effort)."""
    try:
        r = requests.get(CRTSH_JSON.format(domain=domain), timeout=8)
        if r.status_code == 200:
            entries = r.json()
            subs = set()
            for e in entries:
                name = e.get("name_value", "") or e.get("common_name", "")
                if name:
                    for line in str(name).splitlines():
                        line = line.strip()
                        if line:
                            subs.add(line)
            return sorted(subs)
    except Exception:
        return []
    return []

def bruteforce_subdomains(domain):
    subs = []
    for p in COMMON_PREFIXES:
        subs.append(f"{p}.{domain}")
    return subs

def resolve_host(host):
    try:
        answers = dns.resolver.resolve(host, "A", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []

def discover_subdomains(target_url, logger=None):
    logger = logger or (lambda m: None)
    parsed = urlparse(target_url)
    ext = tldextract.extract(parsed.netloc)
    if not ext.domain or not ext.suffix:
        return []
    domain = f"{ext.domain}.{ext.suffix}"
    logger(f"Discovering subdomains for {domain} via crt.sh")
    found = set(crtsh_subdomains(domain))
    # add bruteforce guesses
    found.update(bruteforce_subdomains(domain))
    results = []
    for h in sorted(found):
        ips = resolve_host(h)
        results.append({"hostname": h, "ips": ips})
    return results
