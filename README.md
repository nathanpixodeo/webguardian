# 🔒 WebGuardian - Malware & Security Scanner

**WebGuardian** is a comprehensive security scanning tool designed to detect malware, backdoors, vulnerabilities, and security misconfigurations in PHP-based web applications, including **WordPress**, **Laravel**, **Symfony**, and other CMS/framework projects.

> **Language:** English (full documentation)  
> **Author:** WebGuardian Team  
> **License:** MIT

---

## ✨ Features

### 🦠 Malware Detection
- **Signature-based scanning** — known malware patterns, web shells, and backdoors
- **Heuristic analysis** — behavior-based scoring to detect suspicious code that may not match known signatures
- **Obfuscation detection** — identifies base64-encoded payloads, hex-encoded strings, nested deobfuscation functions (`gzinflate`, `str_rot13`, `gzuncompress`)
- **Cryptojacking detection** — finds cryptocurrency mining scripts and mining pool connections

### 🎯 CMS-Specific Scanning
| CMS | Checks |
|-----|--------|
| **WordPress** | Core integrity, version vulnerabilities, plugin/theme analysis, upload directory security, wp-config hardening, user enumeration, must-use plugin inspection |
| **Laravel** | `.env` exposure, APP_KEY strength, debug mode, route exposure, middleware config, composer package audit, service provider analysis |
| **Generic PHP** | Composer integrity, `.htaccess` security, `.git` exposure, `php.ini` misconfigurations, backup files, information disclosure |

### 🛡️ Vulnerability Detection
- **SQL Injection** — unsanitized input in database queries (CWE-89)
- **Cross-Site Scripting (XSS)** — echoed user input without escaping (CWE-79)
- **Local File Inclusion (LFI)** — user-controlled `include()`/`require()` (CWE-98)
- **Server-Side Request Forgery (SSRF)** — user-controlled URLs in HTTP clients (CWE-918)
- **Insecure Deserialization** — `unserialize()` with user input (CWE-502)
- **Header Injection** — user input in HTTP headers (CWE-113)

### 📊 Reporting
- **Console output** — colorized terminal report with severity breakdown
- **JSON export** — machine-readable structured data for CI/CD integration
- **HTML report** — production-grade dashboard with severity badges and statistics
- **Severity classification** — Critical / High / Medium / Low / Info

> The project is currently in active development. The rule engine is **extensible** and allows adding custom detection patterns without modifying the core code.

---

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Platform Detection](#platform-detection)
- [Output Formats](#output-formats)
- [Extending Rules](#extending-rules)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Integration](#integration)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

---

## 🚀 Installation

### Requirements

- PHP 8.0 or higher
- `ext-json`
- `ext-mbstring`
- Composer (for dependency management)

### Via Composer

```bash
composer create-project webguardian/scanner my-security-scan
```

### Manual Installation

```bash
git clone https://github.com/webguardian/scanner.git
cd webguardian
composer install
```

### Quick Install (No Composer)

```bash
git clone https://github.com/webguardian/scanner.git
cd webguardian
php bin/webguardian scan /path/to/scan
```

---

## ⚡ Quick Start

Scan a WordPress site:

```bash
php bin/webguardian scan /var/www/html --type=wordpress
```

Scan a Laravel application with verbose output:

```bash
php bin/webguardian scan /var/www/myapp --type=laravel --verbose
```

Auto-detect CMS type and generate HTML report:

```bash
php bin/webguardian scan /var/www/html --format=html --output=report.html
```

---

## 📖 Usage

### Command Line Interface

```
webguardian scan <path> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--type=<type>` | CMS type: `auto`, `wordpress`, `laravel`, `generic` | `auto` |
| `--format=<format>` | Output format: `console`, `json`, `html` | `console` |
| `--output=<file>` | Write report to file | stdout |
| `--depth=<num>` | Maximum scan depth | `10` |
| `--no-backup` | Skip backup file scanning | false |
| `--no-perm` | Skip permission checks | false |
| `--verbose` | Verbose output showing scan progress | false |
| `--rules=<path>` | Custom rules directory | built-in |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No issues found |
| `1` | Issues found (medium/low/info) |
| `2` | Critical or High severity issues found |

### Examples

#### Basic WordPress Scan

```bash
php bin/webguardian scan /var/www/mysite
```

Expected output:
```
  ════════════════════════════════════════════════════════
  WebGuardian Security Scan Report
  ════════════════════════════════════════════════════════

  Scan Path:    /var/www/mysite
  CMS Type:     wordpress
  Scan Time:    2026-06-15T10:30:00+00:00
  Duration:     2340ms
  Files Scanned: 1842

  ┌─ Scan Summary ──────────────────────────────
  │
  │   Critical: 0
  │   High:     3  ███
  │   Medium:   5  █████
  │   Low:      2  ██
  │   Info:     1  █
  │
  │   Total Findings: 11
  └────────────────────────────────────────────────
```

#### JSON Output for CI/CD

```bash
php bin/webguardian scan /var/www/html --format=json --output=scan-report.json
```

Then integrate with your CI pipeline:

```yaml
# .github/workflows/security-scan.yml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run WebGuardian Scan
        run: |
          php webguardian scan . --format=json --output=report.json
          if [ $? -eq 2 ]; then exit 1; fi
```

#### Scanning Remote Directories via SSH

```bash
ssh user@server "php /path/to/webguardian scan /var/www --format=json" > remote-scan.json
```

---

## 🧠 Platform Detection

WebGuardian auto-detects the CMS type:

| Indicator | Detected Type |
|-----------|---------------|
| `wp-config.php` exists | **WordPress** |
| `artisan` exists + `app/` directory | **Laravel** |
| None of the above | **Generic PHP** |

You can override detection with `--type=<type>`.

---

## 📄 Output Formats

### Console Format
Colorized terminal output with severity-bucketed findings, progress information, and a summary dashboard. Includes ANSI color codes for readability.

### JSON Format
Structured data ideal for CI/CD pipelines and automated processing:

```json
{
  "metadata": {
    "scanned_at": "2026-06-15T10:30:00+00:00",
    "path": "/var/www/html",
    "type": "wordpress",
    "duration_ms": 2340,
    "files_scanned": 1842,
    "scanner_version": "1.0.0"
  },
  "summary": {
    "critical": 0,
    "high": 3,
    "medium": 5,
    "low": 2,
    "info": 1,
    "total": 11
  },
  "findings": [
    {
      "file": "/var/www/html/wp-content/plugins/evil.php",
      "line": 42,
      "pattern": "base64_eval",
      "severity": "critical",
      "type": "malware",
      "message": "eval() wrapping base64_decode() - classic PHP malware deobfuscation pattern",
      "context": "eval(base64_decode($_POST['cmd']));"
    }
  ]
}
```

### HTML Format
A production-grade responsive dashboard featuring:
- Severity-colored status banner
- Statistics grid with severity counts
- Detailed findings table
- Meta information panel
- Export-friendly layout

---

## 🔌 Extending Rules

### JSON Rule Files

Place custom rules in a directory and reference with `--rules=<path>`:

```json
{
  "version": "1.0.0",
  "patterns": [
    {
      "id": "my_custom_pattern",
      "pattern": "suspicious_function\\s*\\(",
      "severity": "high",
      "type": "custom",
      "message": "My custom detection rule"
    }
  ]
}
```

### Rule Structure

| Field | Description | Required |
|-------|-------------|----------|
| `id` | Unique identifier for the rule | ✅ |
| `pattern` | Regex pattern to match | ✅ |
| `severity` | `critical`, `high`, `medium`, `low`, `info` | ✅ |
| `type` | Category of the finding | ✅ |
| `message` | Human-readable description | ✅ |
| `multiLine` | If true, scans entire file content | ❌ |
| `negative` | If true, checks for absence of pattern | ❌ |

### Programmatic Extension

```php
use WebGuardian\Scanner;

$scanner = new Scanner('/path/to/scan', [
    'rules' => '/path/to/custom/rules'
]);
$results = $scanner->run();
```

---

## 🏗️ Architecture

```
webguardian/
├── bin/
│   └── webguardian          # CLI entry point
├── src/
│   ├── Scanner.php           # Main scanner orchestrator
│   ├── Scanner/
│   │   ├── WordPressScanner.php
│   │   ├── LaravelScanner.php
│   │   └── GenericScanner.php
│   ├── Detector/
│   │   ├── MalwareDetector.php
│   │   ├── BackdoorDetector.php
│   │   └── VulnerabilityDetector.php
│   ├── Analyzer/
│   │   ├── FileAnalyzer.php
│   │   └── DatabaseAnalyzer.php
│   └── Report/
│       ├── ReportGenerator.php
│       └── Formatters/
│           ├── ConsoleFormatter.php
│           ├── JsonFormatter.php
│           └── HtmlFormatter.php
├── rules/
│   ├── malware-patterns.json
│   ├── wordpress-suspicious.json
│   ├── laravel-backdoors.json
│   └── generic-threats.json
├── public/
│   └── index.php             # Web dashboard (Tailwind CSS)
├── tests/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── USAGE.md
│   ├── RULES.md
│   └── CONTRIBUTING.md
├── composer.json
├── LICENSE
└── README.md
```

### Data Flow

```
User Input (path + options)
         │
         ▼
   Scanner (orchestrator)
         │
         ├──► CMS Scanner ──► WordPress / Laravel / Generic
         │
         ├──► File Walker ──► FilesystemIterator
         │
         ├──► MalwareDetector ──► Signature matching + heuristics
         │
         ├──► BackdoorDetector ──► Scoring-based detection
         │
         ├──► VulnerabilityDetector ──► Pattern matching (SQLi, XSS, LFI, SSRF)
         │
         ├──► FileAnalyzer ──► Permissions, sensitive data
         │
         └──► DatabaseAnalyzer ──► Config exposure, SQL dumps
                  │
                  ▼
         ReportGenerator
                  │
                  ▼
         Formatter ──► Console / JSON / HTML
```

---

## 🔍 Detection Engine Details

### Signature-Based Detection
The scanner maintains a database of known malware signatures, web shell fingerprints, and exploit patterns. These are regex patterns that target specific code patterns commonly found in malicious software.

### Heuristic (Scoring) Detection
The backdoor detector assigns weighted scores to each line of code based on the presence of dangerous functions, obfuscation techniques, and suspicious patterns. Lines exceeding a configurable threshold (default: 70) are flagged.

**Scoring Weights:**

| Feature | Weight |
|---------|--------|
| `eval()` | 50 |
| System command execution | 40 |
| File write with user input | 25 |
| Base64 obfuscation | 10 |
| Network operations | 15 |
| User input in dangerous context | 30 |
| Multiple dangerous functions per line | +15 each |

### Vulnerability Pattern Matching
The vulnerability detector scans for common web application security flaws using regex patterns mapped to CWE identifiers:
- SQL Injection → CWE-89
- XSS → CWE-79
- LFI → CWE-98
- SSRF → CWE-918
- Header Injection → CWE-113
- Insecure Deserialization → CWE-502

### CMS-Specific Analysis
WordPress and Laravel scanners include framework-specific checks that go beyond generic pattern matching, analyzing core file integrity, configuration hardening, and known vulnerability vectors.

---

## 🔗 Integration

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
      - name: Install WebGuardian
        run: |
          git clone https://github.com/webguardian/scanner.git
          cd scanner && composer install --no-dev
      - name: Run Security Scan
        run: |
          php scanner/bin/webguardian scan . --format=json --output=report.json
          if [ $? -eq 2 ]; then
            echo "::error::Critical or High severity issues found!"
            cat report.json
            exit 1
          fi
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
php /path/to/webguardian scan --staged --format=json > /dev/null
if [ $? -eq 2 ]; then
    echo "ERROR: Security issues detected in staged changes!"
    exit 1
fi
```

### Monitoring Script

```bash
#!/bin/bash
# Scheduled scan with email notification
php /opt/webguardian/bin/webguardian scan /var/www --format=json > /tmp/scan.json
if [ $? -ge 2 ]; then
    mail -s "Security Alert: Issues found on $(hostname)" admin@example.com < /tmp/scan.json
fi
```

---

## ❓ FAQ

### How does WebGuardian detect malware?
It uses a combination of signature-based pattern matching (known malware patterns), heuristic scoring (behavioral analysis), and CMS-specific checks.

### Does it scan database contents?
Currently, WebGuardian scans filesystem-level code. Database scanning is planned for a future release.

### Can it be used in production?
Yes. WebGuardian is designed for production use. It performs read-only operations and does not modify any files.

### How often are detection rules updated?
Built-in rules are updated with each release. You can also maintain your own custom rules directory.

### Does it require internet access?
No. All scanning is performed locally. No data is sent to external servers.

### Can it scan non-PHP files?
Yes, WebGuardian scans various file types including JS, HTML, .htaccess, .env, and configuration files for relevant security issues.

---

## 🤝 Contributing

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

### Development Setup

```bash
git clone https://github.com/webguardian/scanner.git
cd webguardian
composer install
composer test
```

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

WebGuardian performs static code analysis and may produce both false positives and false negatives. Always review findings manually before taking action. The authors are not responsible for any damage resulting from the use of this tool.

---

<p align="center">Built with ❤️ for the security community</p>
