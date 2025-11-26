# scanner/crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def discover_forms_and_links(start_url, max_depth=1, logger=None):
    """
    Simple BFS crawl that returns a list of dicts: {url, forms, links}.
    Note: same-host restriction is applied.
    """
    logger = logger or (lambda m: None)
    parsed = urlparse(start_url)
    base_host = parsed.netloc
    seen = set()
    queue = [(start_url, 0)]
    results = []

    session = requests.Session()
    headers = {'User-Agent': 'TheWescan/0.1 (+intern)'}

    while queue:
        url, depth = queue.pop(0)
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        logger(f'Fetching {url} (depth {depth})')
        try:
            r = session.get(url, headers=headers, timeout=8)
            soup = BeautifulSoup(r.text, 'lxml')
            forms = []
            for form in soup.find_all('form'):
                action = form.get('action') or url
                method = form.get('method', 'get').lower()
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if not name:
                        continue
                    itype = inp.get('type') or 'text'
                    inputs.append({'name': name, 'type': itype})
                forms.append({'action': urljoin(url, action), 'method': method, 'inputs': inputs})
            links = []
            for a in soup.find_all('a', href=True):
                href = urljoin(url, a['href'])
                parsed_href = urlparse(href)
                if parsed_href.netloc == base_host:
                    links.append(href)
                    if href not in seen:
                        queue.append((href, depth + 1))
            results.append({'url': url, 'forms': forms, 'links': links})
        except Exception as e:
            logger(f'Failed to fetch {url}: {e}')
    return results
