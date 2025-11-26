# TheWescan – Web Application Vulnerability Scanner

## ⚠️ Legal & Ethical Notice

**TheWescan is strictly for educational and research purposes only.**

It is designed and tested only on intentionally vulnerable platforms including:

* [http://testphp.vulnweb.com](http://testphp.vulnweb.com)
* DVWA (Damn Vulnerable Web Application)
* Local lab or controlled environments

Do **not** run this tool against real-world, third‑party, production websites without explicit written authorization. Unauthorized scanning is illegal and against ethical hacking standards.

---

# 📌 Project Overview

TheWescan is a self‑hosted, open‑source web application vulnerability scanner written in **Python + Flask**. It performs security tests on a target URL and reports vulnerabilities in a structured and interactive web dashboard.

The goal of this project is to:

* Help students and cyber‑security beginners understand common web‑based attacks
* Provide an automated way to detect vulnerabilities in lab targets
* Learn secure coding, web penetration testing, and defensive development

This project was built as a self‑learning cybersecurity internship project.

---

# ✨ Features

✔ Fully working modern Flask-based web UI
✔ Live logging and real-time status updates while scanning
✔ Detects common web vulnerabilities including:

* **XSS** (Reflected attacks)
* **SQL Injection (SQLi)**
* **Local File Inclusion (LFI)**
* **XML External Entity Attack (XXE)**
* **JSON / API endpoint testing**
* **Subdomain enumeration**

✔ Automatically finds forms and input parameters
✔ Crawls for endpoints and JavaScript API routes
✔ Multi-module scanning engine
✔ PDF Report export with:

* PoC payloads
* Evidence
* Mitigation suggestions

---

# 🧱 Project Architecture

```
TheWescan/
│   app.py                 → Flask Web App
│   models.py              → SQLAlchemy database models
│   thewescan.db           → SQLite DB
│   requirements.txt       → All dependencies
│
├── scanner/               → Vulnerability Modules
│   crawler.py             → URL & form crawler
│   xss.py                 → Reflected XSS checks
│   sqli.py                → SQL Injection checks
│   lfi.py                 → Local File Inclusion tests
│   xxe.py                 → XXE payload tests
│   subdomain.py           → Subdomain enumeration
│   report.py              → PDF report generator
│
├── templates/             → HTML templates
│   index.html
│   scan.html
│
└── static/                → Theme and CSS
    style.css
```

---

# 🛠️ Installation

## 1. Clone the repository

```
git clone https://github.com/<yourusername>/TheWescan
cd TheWescan
```

## 2. Create a virtual environment

```
python -m venv venv
```

### Windows:

```
venv\Scripts\activate
```

### Linux/Mac:

```
source venv/bin/activate
```

## 3. Install dependencies

```
pip install -r requirements.txt
```

## 4. Initialize the database

```
python -c "from models import init_db; init_db(); print('DB initialized')"
```

## 5. Run the scanner

```
python app.py
```

Then open the browser and visit:

```
http://127.0.0.1:5000
```

---

# 🧪 Supported Targets (Safe for Scanning)

You can safely run scans on:

* [http://testphp.vulnweb.com](http://testphp.vulnweb.com)
* DVWA (Local Machine)
* Other intentionally vulnerable apps (Juice Shop with enhanced mode)

These environments are designed for learning and do not impact real users or systems.

---

# 🧠 How the Scanner Works

### 1. Crawl the website

* Identifies forms, inputs, and parameters
* Searches for subdomains
* Parses JavaScript files for API endpoints

### 2. Test for vulnerabilities

Examples:

```
XSS:
  <script>alert(1)</script>

SQLi:
  ' OR 1=1 --

LFI:
  ../../etc/passwd

XXE:
  <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

### 3. Log results in real time

While scanning, logs are streamed live to the UI.

### 4. Generate a detailed report

* Includes PoC and mitigation suggestions

---

# 📄 PDF Report Example

The exported report contains:

* Scan summary
* Vulnerability list
* Payloads used
* Evidence snippet
* Mitigation guidance

---

# 🧰 Roadmap / Future Features

* Authentication scanning
* Crawler for SPAs and heavy JS apps
* CSRF and Open Redirect detection
* Headless browser scanning
* Multiple scan profiles & advanced UI

---

# ❌ Disclaimer

This tool is created purely for:

* **Education**
* **Research**
* **Learning and training**

Unauthorized scanning of websites is:

* Illegal
* Unethical
* Against professional cybersecurity guidelines

Only use TheWescan on authorized and legal targets.

---

# 🧑‍💻 Author
Hemant Sirvee

Developed as a cyber security learning project.

If you want to use, contribute, or improve the tool, feel free to fork the repo!

---

# ⭐ Contribute

Feel free to submit PRs or suggestions. All contributions are welcome.

---

# 💬 Final Words

This project is designed to help beginners learn web pentesting concepts the right way. Use it wisely, safely, and legally.

Stay curious. Stay ethical. Happy hacking!
