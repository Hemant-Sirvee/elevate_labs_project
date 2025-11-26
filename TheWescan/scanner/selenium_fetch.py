# scanner/selenium_fetch.py
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import time
from urllib.parse import urljoin

def render_and_extract(url, wait=2):
    opts = Options()
    opts.headless = True
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Chrome(ChromeDriverManager().install(), options=opts)
    driver.get(url)
    time.sleep(wait)   # let JS load; increase if network slow
    # extract form actions and inputs
    forms = []
    for form in driver.find_elements_by_tag_name("form"):
        action = form.get_attribute("action") or url
        method = form.get_attribute("method") or "get"
        inputs = []
        for inp in form.find_elements_by_tag_name("input"):
            name = inp.get_attribute("name")
            itype = inp.get_attribute("type") or "text"
            if name:
                inputs.append({"name": name, "type": itype})
        forms.append({"action": urljoin(url, action), "method": method.lower(), "inputs": inputs})
    # optionally: extract XHRs via performance logs (advanced) or look for data-* attributes
    driver.quit()
    return forms
