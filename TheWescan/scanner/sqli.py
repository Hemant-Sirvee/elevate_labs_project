# scanner/sqli.py
import requests
import re

SQLI_ERRORS = re.compile(r"(you have an error in your sql syntax|mysql_fetch|mysql_num_rows|syntax error|Unhandled exception|SQL syntax|ODBC|SQLSTATE)", re.I)

INJ_PAYLOADS = ["' OR '1'='1", "' OR 1=1 -- ", '" OR "1"="1']

def test_sqli_on_param(url, param_name, session=None, timeout=8):
    """
    Basic GET param SQLi test. Returns finding dict on possible evidence.
    """
    s = session or requests.Session()
    try:
        # baseline
        r_base = s.get(url, timeout=timeout)
        base_len = len(r_base.text)
        for p in INJ_PAYLOADS:
            params = {param_name: p}
            r = s.get(url, params=params, timeout=timeout)
            if SQLI_ERRORS.search(r.text) or abs(len(r.text) - base_len) > 300:
                return {'param': param_name, 'payload': p, 'evidence': r.text[:800]}
    except Exception:
        return None
    return None
