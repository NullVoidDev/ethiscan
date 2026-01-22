# EthiScan - Ethical Web Vulnerability Scanner

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/version-2.0-green.svg" alt="Version 2.0">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
</p>

<p align="center">
  <strong>A professional, modular web vulnerability scanner for ethical security assessments.</strong>
</p>

---

## ⚠️ ETHICAL USE DISCLAIMER

> **IMPORTANT: This tool is designed for AUTHORIZED security testing ONLY.**

By using EthiScan, you agree to the following:

- ✅ You have **explicit written permission** to test the target system
- ✅ You understand the **legal implications** of security testing
- ✅ You will use findings **responsibly** for improving security
- ❌ You will **NOT** use this tool for malicious purposes

**Unauthorized access to computer systems is ILLEGAL in most jurisdictions.**

---

## 🚀 What's New in v2.0

- **🔍 New Modules**: CORS misconfiguration, Technology fingerprinting
- **📊 Security Score**: 0-100 score with letter grades (A+ to F)
- **🕷️ Crawling**: Follow internal links with configurable depth
- **📈 Chart.js Reports**: Beautiful HTML reports with pie charts
- **🔐 Authentication**: Custom cookies and headers support
- **⚡ Severity Filter**: Focus on critical issues only
- **🌐 i18n**: English and Portuguese (pt-br) support

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ethiscan.git
cd ethiscan

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run EthiScan
python -m ethiscan --help
```

---

## 🔧 Usage

### Basic Scan

```bash
# Simple passive scan
python -m ethiscan scan --url https://example.com

# Generate HTML report with charts
python -m ethiscan scan --url https://example.com --format html

# Generate all report formats
python -m ethiscan scan --url https://example.com --format all
```

### Crawling Multiple Pages

```bash
# Crawl and scan up to 20 pages (depth 1)
python -m ethiscan scan --url https://example.com --crawl-depth 1

# Deep crawl with custom limits
python -m ethiscan scan --url https://example.com --crawl-depth 2 --max-pages 50
```

### Filtering Results

```bash
# Only show HIGH and CRITICAL vulnerabilities
python -m ethiscan scan --url https://example.com --severity HIGH

# Only show CRITICAL
python -m ethiscan scan --url https://example.com --severity CRITICAL
```

### Authentication

```bash
# With cookies
python -m ethiscan scan --url https://example.com --cookie "session=abc123" --cookie "token=xyz"

# With custom headers
python -m ethiscan scan --url https://example.com --header "Authorization: Bearer token123"

# Both
python -m ethiscan scan --url https://example.com --cookie "session=abc" --header "X-API-Key: secret"
```

### Debug Commands

```bash
# List all modules
python -m ethiscan list-modules

# View headers from a URL
python -m ethiscan headers --url https://example.com
```

### Language

```bash
# Use Portuguese (Brazil)
python -m ethiscan --lang pt-br scan --url https://example.com
```

---

## 📊 Security Score

EthiScan calculates a 0-100 security score based on:

| Component | Weight | Description |
|-----------|--------|-------------|
| Security Headers | 40% | Presence and configuration of CSP, HSTS, etc. |
| Cookie Security | 20% | Secure, HttpOnly, SameSite flags |
| Vulnerabilities | 40% | Penalty for each finding by severity |

### Grades

| Score | Grade | Status |
|-------|-------|--------|
| 95+ | A+ | Excellent |
| 90-94 | A | Very Good |
| 80-89 | B+ | Good |
| 70-79 | B | Satisfactory |
| 60-69 | C | Fair |
| 50-59 | D | Poor |
| <50 | F | Critical |

---

## 🔍 Scanning Modules

### Passive Modules (Always Run)

| Module | Description |
|--------|-------------|
| `headers` | Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.) |
| `cookies` | Analyzes cookie security flags |
| `server_info` | Detects version disclosure, sensitive comments, debug mode |
| `cors` | CORS misconfiguration detection |
| `technology` | Framework/CMS/CDN fingerprinting |

### Active Modules (Require --active)

| Module | Description |
|--------|-------------|
| `xss` | Tests for reflected XSS |
| `sqli` | Tests for SQL injection |

---

## 📝 CLI Options

```
python -m ethiscan scan [OPTIONS]

Required:
  -u, --url TEXT          Target URL to scan

Options:
  -o, --output TEXT       Output file name (default: report)
  -f, --format TEXT       Report format: txt, json, html, pdf, all
  --active                Enable active scanning (XSS, SQLi)
  --severity LEVEL        Filter: INFO, LOW, MEDIUM, HIGH, CRITICAL
  --crawl-depth N         Crawl depth: 0-3 (default: 0)
  --max-pages N           Max pages to crawl (default: 20)
  --delay SECONDS         Delay between requests (default: 0.5)
  --cookie "name=val"     Add cookie (repeatable)
  --header "Name: Val"    Add header (repeatable)
  --timeout SECONDS       Request timeout (default: 10)
  --no-verify-ssl         Disable SSL verification
  --log-file PATH         Save logs to file
  -c, --config PATH       Custom config file
  -y, --yes               Skip confirmation prompts
  -q, --quiet             Minimal output
  --lang LANG             Language: en, pt-br
```

---

## 📁 Project Structure

```
ethiscan/
├── ethiscan/
│   ├── core/
│   │   ├── config.py      # Configuration
│   │   ├── crawler.py     # Web crawler
│   │   ├── i18n.py        # Translations
│   │   ├── logger.py      # Logging
│   │   ├── models.py      # Data models
│   │   ├── scoring.py     # Security score
│   │   └── utils.py       # Utilities
│   ├── modules/
│   │   ├── headers.py     # Security headers
│   │   ├── cookies.py     # Cookie security
│   │   ├── cors.py        # CORS checks
│   │   ├── server_info.py # Server fingerprinting
│   │   ├── technology.py  # Tech fingerprinting
│   │   ├── xss.py         # XSS scanner (active)
│   │   └── sqli.py        # SQLi scanner (active)
│   ├── reporters/
│   │   ├── html.py        # HTML + Chart.js
│   │   ├── json.py        # JSON
│   │   ├── pdf.py         # PDF
│   │   └── txt.py         # Plain text
│   ├── scanners/
│   │   └── web_scanner.py # Main scanner
│   └── cli/
│       └── parser.py      # CLI interface
├── config/
│   └── default.yaml       # Default config
├── tests/
├── requirements.txt
├── Dockerfile
└── README.md
```

---

## 🧪 Testing with DVWA

[DVWA](https://github.com/digininja/DVWA) is a deliberately vulnerable web application.

```bash
# Start DVWA
docker run --rm -d -p 80:80 vulnerables/web-dvwa

# Passive scan
python -m ethiscan scan --url http://localhost/dvwa --format html

# With crawling
python -m ethiscan scan --url http://localhost/dvwa --crawl-depth 1 --format html

# Active scan (after permission!)
python -m ethiscan scan --url http://localhost/dvwa --active --format all
```

---

## 🐳 Docker

```bash
# Build
docker build -t ethiscan .

# Run
docker run --rm ethiscan scan --url https://example.com
```

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>⚠️ Always get proper authorization before testing any system! ⚠️</strong>
</p>
