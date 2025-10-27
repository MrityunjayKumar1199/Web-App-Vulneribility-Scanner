"""
Web Application Vulnerability Scanner
Detects simple XSS and SQL Injection vulnerabilities using payload tests.
Educational proof-of-concept for ethical testing.
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1 --", "\" OR \"1\"=\"1", "';--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"]

class WebVulnScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.vulnerabilities = []

    def get_all_forms(self, url):
        """Crawl and return all form tags from a page"""
        try:
            res = self.session.get(url, timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"[!] Error fetching forms from {url}: {e}")
            return []

    def form_details(self, form):
        """Extract details from form tag"""
        details = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            name = input_tag.attrs.get("name")
            typ = input_tag.attrs.get("type", "text")
            val = input_tag.attrs.get("value", "")
            inputs.append({"name": name, "type": typ, "value": val})
        details['action'] = action
        details['method'] = method
        details['inputs'] = inputs
        return details

    def submit_form(self, form_details, url, payload):
        """Submit payload to form and return response"""
        target = urljoin(url, form_details['action'])
        data = {}
        for inp in form_details['inputs']:
            if inp['type'] in ["text", "search", "email"]:
                data[inp['name']] = payload
            else:
                data[inp['name']] = inp['value']
        if form_details['method'] == 'post':
            return self.session.post(target, data=data, timeout=5)
        else:
            return self.session.get(target, params=data, timeout=5)

    def scan_xss(self, url):
        """Detect reflected XSS"""
        forms = self.get_all_forms(url)
        for form in forms:
            details = self.form_details(form)
            for payload in XSS_PAYLOADS:
                res = self.submit_form(details, url, payload)
                if payload in res.text:
                    self.vulnerabilities.append({
                        "type": "XSS",
                        "payload": payload,
                        "url": url,
                        "evidence": payload
                    })
                    print(f"[+] XSS Found on {url}")
                    break

    def scan_sqli(self, url):
        """Detect SQLi via response patterns"""
        error_patterns = ["sql syntax", "mysql", "ORA-", "syntax error", "Warning: mysql_"]
        for payload in SQLI_PAYLOADS:
            full_url = f"{url}?id={payload}"
            try:
                res = self.session.get(full_url, timeout=5)
                if any(err.lower() in res.text.lower() for err in error_patterns):
                    self.vulnerabilities.append({
                        "type": "SQLi",
                        "payload": payload,
                        "url": full_url
                    })
                    print(f"[+] SQLi Found: {full_url}")
                    break
            except Exception:
                pass

    def crawl_and_scan(self):
        print(f"[*] Scanning {self.base_url}")
        self.scan_xss(self.base_url)
        self.scan_sqli(self.base_url)
        return self.vulnerabilities


if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://testphp.vulnweb.com): ").strip()
    scanner = WebVulnScanner(target)
    vulns = scanner.crawl_and_scan()
    print("\n=== Scan Summary ===")
    if vulns:
        for v in vulns:
            print(v)
    else:
        print("No vulnerabilities found (basic scan).")
