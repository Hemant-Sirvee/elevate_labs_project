# scanner/js_endpoints.py
import requests
import re
from urllib.parse import urljoin, urlparse

# regexes to find fetch/XHR endpoints and common API patterns
FETCH_RE = re.compile(r'''fetch\(\s*['"]([^'"]+)['"]''', re.I)
XHR_RE = re.compile(r'''xhr\.open\(\s*['"](?:GET|POST|PUT|DELETE)['"]\s*,\s*['"]([^'"]+)['"]''', re.I)
AJAX_RE = re.compile(r'''ajax\(\s*['"]([^'"]+)['"]''', re.I)
URL_RE = re.compile(r'''['"]((?:/|https?://)[\w\-\./\?\=\&%]+)['"]''')

def extract_endpoints_from_js(js_text, base_url):
    urls = set()
    for m in FETCH_RE.finditer(js_text):
        urls.add(m.group(1))
    for m in XHR_RE.finditer(js_text):
        urls.add(m.group(1))
    for m in AJAX_RE.finditer(js_text):
        urls.add(m.group(1))
    # also catch any quoted absolute/relative urls
    for m in URL_RE.finditer(js_text):
        urls.add(m.group(1))
    # normalize
    norm = []
    for u in urls:
        # ignore data: and mailto:
        if u.startswith("data:") or u.startswith("mailto:"):
            continue
        # join relative to base
        norm.append(urljoin(base_url, u))
    # filter to same-host
    parsed_base = urlparse(base_url)
    norm = [u for u in norm if urlparse(u).netloc == parsed_base.netloc]
    return sorted(set(norm))


def find_js_and_extract(url, session=None, timeout=8):
    s = session or requests.Session()
    try:
        r = s.get(url, timeout=timeout)
        html = r.text
        # find <script src="">
        script_urls = []
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            script_urls.append(m.group(1))
        endpoints = set()
        for src in script_urls:
            full = urljoin(url, src)
            try:
                jr = s.get(full, timeout=8)
                endpoints.update(extract_endpoints_from_js(jr.text, url))
            except Exception:
                continue
        # also try inline scripts
        for m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.I | re.S):
            endpoints.update(extract_endpoints_from_js(m.group(1), url))
        return sorted(endpoints)
    except Exception:
        return []
