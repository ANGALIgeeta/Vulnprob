# 🔍 VulnProbe — Web Vulnerability Scanner

A portfolio-worthy web application security scanner built with Python (Flask) + Vanilla JavaScript.
Scans websites for common vulnerabilities and displays results in a real-time dashboard.

---

## 🚀 Features

- **Security Header Analysis** — Detects 7 missing/weak HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- **Sensitive Path Exposure** — Probes for exposed `.env`, `.git`, `/admin`, `phpinfo.php`, backup files, and more
- **Cookie Security Audit** — Checks for missing `Secure`, `HttpOnly`, and `SameSite` attributes
- **XSS Reflection Detection** — Tests if query parameters reflect unsanitized input in HTML responses
- **SQL Injection Probing** — Injects SQL characters and looks for database error messages
- **Information Disclosure** — Detects server/tech stack leakage via response headers
- **Real-time Progress Dashboard** — Live scan progress with severity-filtered findings
- **JSON Report Export** — Download full scan results

---

## 🛡️ Ethical Use Notice

> **Only scan websites you own or have explicit written permission to test.**
> Unauthorized scanning of systems is illegal in most jurisdictions.
> This tool is built for educational purposes and authorized security testing only.

---

## 📁 Project Structure

```
web-vuln-scanner/
├── backend/
│   ├── app.py          # Flask API server
│   ├── scanner.py      # All vulnerability check modules
│   └── requirements.txt
└── frontend/
    └── index.html      # Dashboard UI (single file)
```

---

## ⚙️ Setup & Run

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Start the backend

```bash
python app.py
```

The API will run on `http://localhost:5000`

### 3. Open the frontend

Open `frontend/index.html` directly in your browser, or serve it:

```bash
# Option A: Python simple server (from project root)
python -m http.server 8080 --directory frontend
# Then visit http://localhost:8080

# Option B: Just open the file
open frontend/index.html
```

### 4. Scan a target

Enter any URL you own (e.g., `http://localhost:8080` or your own domain) and click **Scan Now**.

---

## 🧪 Vulnerability Checks Covered

| Check | OWASP Reference |
|---|---|
| Missing security headers | A05: Security Misconfiguration |
| Exposed sensitive files | A05: Security Misconfiguration |
| Insecure cookies | A02: Cryptographic Failures |
| XSS reflection | A03: Injection |
| SQL Injection | A03: Injection |
| Information disclosure | A05: Security Misconfiguration |

---

## 🔧 Extending the Scanner

Add new checks in `backend/scanner.py` by creating methods on the `Scanner` class and calling them in `run_all()`. Each finding is added via:

```python
self.add_finding(
    category="Category Name",
    name="Finding name",
    severity="HIGH",  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description="What this means",
    remediation="How to fix it",
    detail="Technical detail"
)
```

---

## 📸 Tech Stack

- **Backend**: Python 3, Flask, Requests
- **Frontend**: Vanilla JS, CSS3, Google Fonts
- **No database** — all scan state is in-memory

---

## 💡 Future Improvements

- [ ] Port scanning via `socket`
- [ ] Subdomain enumeration
- [ ] SSL/TLS certificate validation
- [ ] Rate limiting detection
- [ ] Form-based XSS/SQLi testing
- [ ] PDF report generation
- [ ] Docker support
