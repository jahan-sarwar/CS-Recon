# ⚡ CS RECON — Enterprise Automated Reconnaissance & OSINT Framework

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-orange.svg)]()

**CS RECON** is a high-speed, modular, multi-threaded automated reconnaissance & OSINT framework designed for red teamers, penetration testers, and bug bounty hunters. It features zero-dependency native Python fallbacks, WAF detection, subdomain enumeration, port scanning, secret scanning, and interactive glassmorphic HTML reports.

![CS RECON Dashboard Preview](cs_recon_dashboard_preview.jpg)

---

## 🔥 Key Features

- **⚡ Multi-Threaded Reconnaissance Engine**: Parallel target scanning with configurable threads and custom rate limiting.
- **🛡️ WAF & CDN Detection**: Identifies Cloudflare, AWS WAF, Akamai, Imperva, and native firewall signatures.
- **🌐 Subdomain Enumeration**: Integrates passive OSINT sources (crt.sh, HackerTarget, AlienVault) with fallbacks for subfinder and amass.
- **🔌 Intelligent Port & Service Scanning**: Rapid TCP port probes with service banner banner-grabbing and Nmap integration.
- **🔍 Secret & Vulnerability Scanning**: Detects exposed API keys, credentials, CORS misconfigurations, and security headers.
- **📊 Glassmorphic HTML & JSON Reports**: Generates interactive HTML dashboards featuring live charts, filterable tables, and CSV exports.
- **🐧 Cross-Platform Support**: Built-in native Python socket/HTTP fallbacks for zero-dependency operation on Linux, macOS, and Windows.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Optional: `nmap`, `subfinder`, `whatweb`, `gobuster`, `nikto` for enhanced tool probes.

### Installation

1. **Clone the repository:**
   ```bash
   git clone git@github.com:jahan-sarwar/CS-Recon.git
   cd CS-Recon
   ```

2. **Run setup script (Linux / WSL / macOS):**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Install optional Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Usage

### Basic Scan
```bash
python3 cs_recon.py -t example.com
```

### Full Recon Scan with Custom Output
```bash
python3 cs_recon.py -t example.com -o my_report --threads 20 --full
```

### Check Available System Tools & Dependencies
```bash
python3 cs_recon.py --check-deps
```

### View Help Options
```bash
python3 cs_recon.py --help
```

---

## 📁 Project Structure

```
CS-Recon/
├── cs_recon.py                   # Main Framework CLI & Recon Engine
├── cs_recon_dashboard_preview.jpg # Dashboard Preview Screenshot
├── setup.sh                      # Automated Dependencies Installer for Linux/WSL
├── requirements.txt              # Optional Python Dependencies
├── README.md                     # Project Documentation
└── LICENSE                       # MIT License
```

---

## 📄 License

This project is distributed under the [MIT License](LICENSE).
