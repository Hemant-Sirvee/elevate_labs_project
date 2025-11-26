# scanner/json_scan.py
import requests
import re

# simple JSON payloads to try for basic SQLi-like and XSS-like evidence in JSON responses
JSON_PAYLOADS = [
    {"test": "' OR '1'='1"},
    {"test": "\" OR \"1\"=\"1\""},
    {"test": "<script>alert('TW')</script>"},
    {"test": "../../etc/passwd"}
]

# heuristics to detect evidence in JSON (strings that indicate DB error or file content)
SQLI_INDICATORS = re.compile(r"(sql|mysql|syntax error|pdo|sqlstate|mysql_fetch|mysql_num_rows)", re.I)
LFI_INDICATORS = re.compile(r"(root:.*:0:0:|/bin/bash|/etc/passwd)", re.I)
XSS_INDICATORS = re.compile(r"<script|alert\(|onerror=", re.I)

def test_json_endpoint(url, session=None, timeout=8):
    s = session or requests.Session()
    findings = []
    headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "TheWescan/0.1"}
    try:
        # baseline
        try:
            base = s.get(url, headers=headers, timeout=timeout)
            base_text = base.text or ""
        except Exception:
            base_text = ""
        for payload in JSON_PAYLOADS:
            try:
                r = s.post(url, json=payload, headers=headers, timeout=timeout)
            except Exception:
                continue
            text = r.text or ""
            # quick heuristics
            if SQLI_INDICATORS.search(text) and text != base_text:
                findings.append({"payload": payload, "evidence": text[:1000], "type": "sqli-like"})
            elif LFI_INDICATORS.search(text):
                findings.append({"payload": payload, "evidence": text[:1000], "type": "lfi-like"})
            elif XSS_INDICATORS.search(text):
                findings.append({"payload": payload, "evidence": text[:1000], "type": "xss-like"})
            # boolean heuristic: large change in length
            elif abs(len(text) - len(base_text)) > 200:
                findings.append({"payload": payload, "evidence": text[:1000], "type": "diff-response"})
    except Exception:
        return []
    return findings
