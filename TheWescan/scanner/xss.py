# scanner/xss.py
import requests

# Simple reflected XSS test by injecting a unique marker and checking for reflection
MARKER = 'THEWESCAN_XSS_TEST_1234'
PAYLOAD = f'"><script>console.log("{MARKER}")</script>'

def test_reflected_xss(form, session=None, timeout=8):
    """
    Form is a dict with action, method, inputs.
    Returns finding dict when found, otherwise None.
    """
    s = session or requests.Session()
    url = form.get('action')
    data = {}
    for inp in form.get('inputs', []):
        if inp.get('type') in ('submit', 'button', 'image'):
            continue
        data[inp['name']] = PAYLOAD
    try:
        if form.get('method', 'get') == 'post':
            r = s.post(url, data=data, timeout=timeout)
        else:
            r = s.get(url, params=data, timeout=timeout)
        if MARKER in r.text:
            return {
                'param': ','.join([i['name'] for i in form.get('inputs', [])]),
                'payload': PAYLOAD,
                'evidence': r.text[:800]
            }
    except Exception:
        return None
    return None
