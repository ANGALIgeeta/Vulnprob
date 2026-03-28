import requests
import time
import re
from urllib.parse import urljoin, urlparse

# Disable SSL warnings for scanning purposes
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "WebVulnScanner/1.0 (Educational Use Only)"
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS not set. Browser connections may be downgraded to HTTP, enabling man-in-the-middle attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "CSP missing. Attackers can inject malicious scripts (XSS) into your pages.",
        "remediation": "Define a strict CSP policy to whitelist trusted content sources."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Clickjacking protection absent. Your page can be embedded in iframes by attackers.",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "MIME sniffing not blocked. Browsers may misinterpret file types.",
        "remediation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "No referrer policy set. Sensitive URL data may leak to third parties.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Browser feature permissions not restricted (camera, mic, geolocation, etc.).",
        "remediation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS filter header missing. Older browsers may be vulnerable.",
        "remediation": "Add: X-XSS-Protection: 1; mode=block"
    },
}

SENSITIVE_PATHS = [
    ("/.env", "HIGH", "Environment file exposed — may contain DB passwords, API keys, secrets."),
    ("/.git/config", "HIGH", "Git repository config exposed — source code may be accessible."),
    ("/admin", "MEDIUM", "Admin panel found. Ensure it's protected by strong authentication."),
    ("/wp-admin", "MEDIUM", "WordPress admin panel found. Brute-force risk if not rate-limited."),
    ("/phpinfo.php", "HIGH", "phpinfo() exposed — reveals full server config & PHP settings."),
    ("/server-status", "MEDIUM", "Apache server-status page exposed — leaks server internals."),
    ("/config.php", "HIGH", "Config file found — may expose database credentials."),
    ("/backup.zip", "HIGH", "Backup archive found — full site backup may be downloadable."),
    ("/robots.txt", "LOW", "robots.txt found — review for sensitive paths being disclosed."),
    ("/sitemap.xml", "INFO", "sitemap.xml found — useful for mapping the application."),
    ("/.htaccess", "MEDIUM", "Apache config file may be readable — check access rules."),
    ("/api/v1", "INFO", "API endpoint detected — check for authentication and rate limiting."),
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "syntax error",
    "unclosed quotation", "pg_query", "sqlite_", "odbc_",
    "you have an error in your sql", "warning: mysql",
    "division by zero", "supplied argument is not a valid mysql"
]


class Scanner:
    def __init__(self, url, job):
        self.url = url
        self.job = job
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        self.session.timeout = 8

    def add_finding(self, category, name, severity, description, remediation="", detail=""):
        finding = {
            "category": category,
            "name": name,
            "severity": severity,
            "description": description,
            "remediation": remediation,
            "detail": detail,
        }
        self.job["results"].append(finding)

    def update_progress(self, pct):
        self.job["progress"] = pct

    def run_all(self):
        try:
            self.update_progress(5)
            self.check_headers()
            self.update_progress(30)
            self.check_sensitive_paths()
            self.update_progress(60)
            self.check_cookies()
            self.update_progress(75)
            self.check_xss_reflection()
            self.update_progress(88)
            self.check_sqli()
            self.update_progress(100)
            self.job["status"] = "done"
        except Exception as e:
            self.job["status"] = "error"
            self.job["error"] = str(e)

    def check_headers(self):
        try:
            resp = self.session.get(self.url)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, meta in SECURITY_HEADERS.items():
                if header.lower() not in resp_headers:
                    self.add_finding(
                        "Security Headers",
                        f"Missing: {header}",
                        meta["severity"],
                        meta["description"],
                        meta["remediation"],
                        detail=f"Header '{header}' not present in server response."
                    )
                else:
                    # Check for weak values
                    val = resp_headers[header.lower()]
                    if header == "Strict-Transport-Security" and "max-age" in val:
                        age = re.search(r"max-age=(\d+)", val)
                        if age and int(age.group(1)) < 31536000:
                            self.add_finding(
                                "Security Headers",
                                "Weak HSTS max-age",
                                "LOW",
                                "HSTS max-age is less than 1 year, reducing protection window.",
                                "Set max-age to at least 31536000 (1 year).",
                                detail=f"Found: {val}"
                            )

            # Check server/tech disclosure
            for h in ["server", "x-powered-by", "x-aspnet-version"]:
                if h in resp_headers:
                    self.add_finding(
                        "Information Disclosure",
                        f"Tech disclosure via '{h}' header",
                        "LOW",
                        f"Server reveals technology stack: {resp_headers[h]}",
                        f"Remove or obscure the '{h}' header in server config.",
                        detail=f"{h}: {resp_headers[h]}"
                    )

        except requests.RequestException as e:
            self.add_finding("Connectivity", "Failed to reach target", "INFO",
                             f"Could not fetch {self.url}: {e}", "Verify the URL is reachable.")

    def check_sensitive_paths(self):
        for path, severity, description in SENSITIVE_PATHS:
            full_url = urljoin(self.url, path)
            try:
                resp = self.session.get(full_url, allow_redirects=False)
                if resp.status_code in (200, 403):
                    status_note = "accessible (200)" if resp.status_code == 200 else "exists but forbidden (403)"
                    self.add_finding(
                        "Sensitive Path Exposure",
                        f"{path} found",
                        severity,
                        description,
                        "Restrict access via server config or remove the file.",
                        detail=f"GET {full_url} → {resp.status_code} {status_note}"
                    )
            except requests.RequestException:
                pass
            time.sleep(0.1)

    def check_cookies(self):
        try:
            resp = self.session.get(self.url)
            for cookie in resp.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("missing Secure flag")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("missing HttpOnly flag")
                if not cookie.has_nonstandard_attr("SameSite"):
                    issues.append("missing SameSite attribute")

                if issues:
                    self.add_finding(
                        "Cookie Security",
                        f"Insecure cookie: {cookie.name}",
                        "MEDIUM",
                        f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}.",
                        "Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
                        detail=f"Issues: {', '.join(issues)}"
                    )
        except requests.RequestException:
            pass

    def check_xss_reflection(self):
        """Test if query parameters reflect unsanitized user input."""
        test_url = self.url + "?q=XSSTEST_PROBE"
        try:
            resp = self.session.get(test_url)
            if "XSSTEST_PROBE" in resp.text:
                self.add_finding(
                    "Cross-Site Scripting (XSS)",
                    "Reflected input in response",
                    "HIGH",
                    "The server reflects query parameter input directly in the HTML response without sanitization. This is a strong indicator of reflected XSS vulnerability.",
                    "Sanitize and encode all user inputs before reflecting them in HTML output. Use a templating engine with auto-escaping.",
                    detail=f"Probe 'XSSTEST_PROBE' found in response to {test_url}"
                )
        except requests.RequestException:
            pass

    def check_sqli(self):
        """Test URL parameters for SQL error messages indicating injection vulnerability."""
        parsed = urlparse(self.url)
        if parsed.query:
            params = parsed.query.split("&")
            for param in params[:2]:  # test first 2 params only
                key = param.split("=")[0]
                test_url = self.url.replace(param, f"{key}='")
                try:
                    resp = self.session.get(test_url)
                    body_lower = resp.text.lower()
                    for err in SQLI_ERRORS:
                        if err in body_lower:
                            self.add_finding(
                                "SQL Injection",
                                f"Possible SQLi in param: {key}",
                                "CRITICAL",
                                f"SQL error message detected when injecting into parameter '{key}'. This strongly suggests SQL injection vulnerability.",
                                "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
                                detail=f"Error pattern '{err}' found in response."
                            )
                            break
                except requests.RequestException:
                    pass
        else:
            # Try appending a payload to the base URL
            test_url = self.url + "?id='"
            try:
                resp = self.session.get(test_url)
                body_lower = resp.text.lower()
                for err in SQLI_ERRORS:
                    if err in body_lower:
                        self.add_finding(
                            "SQL Injection",
                            "Possible SQLi via id parameter",
                            "CRITICAL",
                            "SQL error detected when testing ?id=' parameter.",
                            "Use parameterized queries. Avoid raw SQL string concatenation.",
                            detail=f"Error pattern '{err}' found."
                        )
                        break
            except requests.RequestException:
                pass
