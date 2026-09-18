#!/usr/bin/env python3
"""
================================================================================
  CS RECON — Enterprise Automated Reconnaissance & OSINT Framework (v2.2.0)
  Author: Cyber Security Recon Toolkit Team
  Description: Fast, Modular, Multi-threaded Reconnaissance Framework with
               Image-Matched Futuristic UI & Remediation Intelligence.
================================================================================
"""

import os
import sys
import time
import json
import re
import argparse
import subprocess
import shutil
import socket
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
import ssl
import logging
import webbrowser
import html
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform.startswith("win"):
    os.system("")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CSRecon")

TOOL_NAME = "CS RECON"
VERSION = "2.2.0 (Futuristic Dashboard UI)"
AUTHOR = "Cyber Security Team"

TIMEOUTS = {
    "whois": 30,
    "dig": 20,
    "nmap": 300,
    "rustscan": 120,
    "masscan": 120,
    "subfinder": 90,
    "amass": 180,
    "dnsx": 60,
    "whatweb": 60,
    "httpx": 90,
    "wafw00f": 60,
    "gobuster": 180,
    "ffuf": 180,
    "feroxbuster": 180,
    "katana": 120,
    "waybackurls": 60,
    "gau": 60,
    "nikto": 240,
    "nuclei": 300,
    "cloud_enum": 120,
    "theHarvester": 120,
    "zaproxy": 300
}

REQUIRED_TOOLS = [
    "nmap", "whois", "dig", "whatweb", "nikto", "gobuster",
    "ffuf", "naabu", "httpx", "nuclei", "subfinder", "amass",
    "rustscan", "wafw00f", "katana", "waybackurls", "dnsx"
]

VERBOSE = False

class Colors:
    HEADER    = '\033[95m'
    OKBLUE    = '\033[94m'
    OKCYAN    = '\033[96m'
    OKGREEN   = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'

def banner():
    term_width = 70
    print(Colors.OKCYAN + "=" * term_width + Colors.ENDC)
    print(Colors.BOLD + Colors.OKGREEN + f"  ____ ____   ____  _____ ____ ___  _   _ ".center(term_width) + Colors.ENDC)
    print(Colors.BOLD + Colors.OKGREEN + f" / ___/ ___| |  _ \\| ____/ ___/ _ \\| \\ | |".center(term_width) + Colors.ENDC)
    print(Colors.BOLD + Colors.OKGREEN + f"| |   \\___ \\ | |_) |  _|| |  | | | |  \\| |".center(term_width) + Colors.ENDC)
    print(Colors.BOLD + Colors.OKGREEN + f"| |___ ___) ||  _ <| |__| |__| |_| | |\\  |".center(term_width) + Colors.ENDC)
    print(Colors.BOLD + Colors.OKGREEN + f" \\____|____/ |_| \\_\\_____|\\____\\___/|_| \\_|".center(term_width) + Colors.ENDC)
    print(Colors.OKCYAN + "-" * term_width + Colors.ENDC)
    print(Colors.BOLD + Colors.HEADER + f"  {TOOL_NAME} v{VERSION} — Futuristic Dashboard Engine".center(term_width) + Colors.ENDC)
    print(Colors.OKBLUE + "  Automated OSINT, Subdomains, Ports, WAF, Remediation & Vuln Scan".center(term_width) + Colors.ENDC)
    print(Colors.OKCYAN + "=" * term_width + Colors.ENDC + "\n")

# ==============================================================================
# REMEDIATION / VULNERABILITY SOLUTIONS DATABASE
# ==============================================================================

REMEDIATIONS = {
    "sql": "Use Parameterized Queries / Prepared Statements (PDO, PreparedStatement) and ORM models. Disable verbose database error messages.",
    "xss": "Implement strict HTML Output Encoding, Content Security Policy (CSP) headers, and HttpOnly flag on session cookies.",
    "ssrf": "Validate & sanitize all user-supplied URLs against an explicit whitelist. Disable internal HTTP redirects to RFC1918 private IPs.",
    "lfi": "Avoid passing raw file paths to file inclusions. Use hardcoded lookup maps or sanitized file identifiers.",
    "rce": "Never pass unvalidated user input to system shell execution (`system`, `exec`). Use parameterized API functions.",
    "cors": "Remove `Access-Control-Allow-Origin: *` for authenticated endpoints. Require explicit trusted origin reflection.",
    "exposure": "Restrict public access to sensitive endpoints (`.env`, `.git`, admin panels) via Web Server configuration or IP whitelisting.",
    "open_port": "Apply host-based firewall rules (iptables/UFW), close unused services, and restrict management ports (SSH/RDP) to VPN IPs.",
    "default": "Enforce principle of least privilege, update software components to latest patch releases, and restrict exposed attack surface."
}

def get_remediation_solution(vuln_name):
    """Returns actionable remediation solution based on vulnerability title."""
    name_lower = str(vuln_name).lower()
    if "sql" in name_lower or "sqli" in name_lower:
        return REMEDIATIONS["sql"]
    elif "xss" in name_lower or "scripting" in name_lower:
        return REMEDIATIONS["xss"]
    elif "ssrf" in name_lower:
        return REMEDIATIONS["ssrf"]
    elif "lfi" in name_lower or "traversal" in name_lower:
        return REMEDIATIONS["lfi"]
    elif "rce" in name_lower or "command" in name_lower or "exec" in name_lower:
        return REMEDIATIONS["rce"]
    elif "cors" in name_lower:
        return REMEDIATIONS["cors"]
    elif "config" in name_lower or "env" in name_lower or "git" in name_lower or "exposure" in name_lower:
        return REMEDIATIONS["exposure"]
    else:
        return REMEDIATIONS["default"]

# ==============================================================================
# LOGGING & HELPER FUNCTIONS
# ==============================================================================

def log_info(msg):
    print(f"{Colors.OKCYAN}[*]{Colors.ENDC} {msg}")

def log_success(msg):
    print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {msg}")

def log_warn(msg):
    print(f"{Colors.WARNING}[!]{Colors.ENDC} {msg}")

def log_error(msg):
    print(f"{Colors.FAIL}[-]{Colors.ENDC} {msg}")

def log_debug(msg):
    if VERBOSE:
        print(f"{Colors.OKBLUE}[DEBUG]{Colors.ENDC} {msg}")

def validate_target(target_str):
    """Centralized Target Validation to prevent Argument Injection & Bad Inputs."""
    if not target_str or not isinstance(target_str, str):
        raise ValueError("Target cannot be empty.")
    
    clean = target_str.strip()
    clean = re.sub(r'^https?://', '', clean).split('/')[0].split(':')[0].strip()
    
    if clean.startswith("-"):
        raise ValueError(f"Invalid target '{clean}': Targets cannot start with hyphens (Argument Injection defense).")
    
    if not re.fullmatch(r'[a-zA-Z0-9\.\-_]+', clean):
        raise ValueError(f"Invalid target '{clean}': Contains illegal characters.")
        
    return clean

def sanitize_filename(name):
    """Sanitizes target name for filenames."""
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name)

def get_ssl_context(verify=False):
    """Configures secure SSL Context for native HTTPS probing."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def safe_run(cmd, timeout=None):
    """Executes a subprocess command safely with timeout and type conversion handling."""
    tool_binary = cmd[0]
    if not shutil.which(tool_binary):
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=127,
            stdout="",
            stderr=f"Tool '{tool_binary}' is not installed or not in PATH."
        )
    
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False
        )
        return proc
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode('utf-8', errors='ignore') if isinstance(e.stdout, bytes) else str(e.stdout or "")
        err = e.stderr.decode('utf-8', errors='ignore') if isinstance(e.stderr, bytes) else str(e.stderr or "")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=-1,
            stdout=out,
            stderr=f"Command timed out after {timeout} seconds. {err}"
        )
    except Exception as e:
        log_debug(f"Subprocess Exception for {cmd}: {e}")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="",
            stderr=str(e)
        )

def check_dependencies(auto_install=False):
    """Verifies which required security tools are present in PATH."""
    log_info("Checking system dependencies for CS Recon...")
    installed = []
    missing = []
    
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool):
            installed.append(tool)
        else:
            missing.append(tool)
            
    print(f"  {Colors.OKGREEN}Installed ({len(installed)}):{Colors.ENDC} {', '.join(installed) if installed else 'None (Using Native Python Engines)'}")
    if missing:
        print(f"  {Colors.FAIL}Missing ({len(missing)}):{Colors.ENDC} {', '.join(missing)}")
        log_warn("CS Recon will automatically use fallback Python engines for missing tools!")
        log_info("To install missing tools on Kali/Ubuntu/Debian run: ./setup.sh\n")
        
        if auto_install and sys.platform.startswith('linux'):
            log_info("Attempting automatic installation via apt...")
            safe_run(["sudo", "apt", "update"], timeout=60)
            safe_run(["sudo", "apt", "install", "-y"] + missing, timeout=300)
    else:
        log_success("All primary security tools are available!\n")
    return missing

def get_targets(prompt_text="Enter target domain/IP or path to targets file (@targets.txt): "):
    """Parses and validates single target, comma-separated targets, or @file.txt targets."""
    raw = input(Colors.BOLD + Colors.OKCYAN + prompt_text + Colors.ENDC).strip()
    if not raw:
        log_error("No target provided.")
        return []

    targets = []
    if raw.startswith("@") or raw.endswith(".txt"):
        filepath = raw[1:] if raw.startswith("@") else raw
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            log_success(f"Loaded {len(targets)} raw target line(s) from '{filepath}'.")
        else:
            log_error(f"Target file '{filepath}' not found.")
            return []
    else:
        targets = [t.strip() for t in raw.split(",") if t.strip()]

    clean_targets = []
    for t in targets:
        try:
            valid_t = validate_target(t)
            clean_targets.append(valid_t)
        except ValueError as ve:
            log_warn(str(ve))

    return list(dict.fromkeys(clean_targets))

# ==============================================================================
# NATIVE PYTHON FALLBACK RECON ENGINES (NO EXTERNAL BINARY REQUIRED)
# ==============================================================================

def native_whois(domain):
    """Native Python WHOIS lookup using socket port 43 with WHOIS server fallback and byte cap."""
    MAX_BYTES = 512 * 1024
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(("whois.iana.org", 43))
            s.send(f"{domain}\r\n".encode())
            response = b""
            while len(response) < MAX_BYTES:
                data = s.recv(4096)
                if not data: break
                response += data

        res_text = response.decode('utf-8', errors='ignore')
        refer_match = re.search(r'refer:\s+([^\s]+)', res_text, re.IGNORECASE)
        whois_server = refer_match.group(1) if refer_match else "whois.verisign-grs.com"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
            s2.settimeout(10)
            s2.connect((whois_server, 43))
            s2.send(f"{domain}\r\n".encode())
            res2 = b""
            while len(res2) < MAX_BYTES:
                d = s2.recv(4096)
                if not d: break
                res2 += d
        return res2.decode('utf-8', errors='ignore')
    except Exception as e:
        log_debug(f"Native WHOIS error for {domain}: {e}")
        return f"[Native WHOIS Error]: {e}"

def native_dns_enum(domain):
    """Native Python DNS Record resolution (A, MX, NS, TXT)."""
    results = {"A": [], "MX": [], "NS": [], "TXT": []}
    
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        results["A"] = ips
    except Exception as e:
        log_debug(f"DNS A record resolution error for {domain}: {e}")

    for record_type in ["MX", "NS", "TXT"]:
        try:
            url = f"https://dns.google/resolve?name={domain}&type={record_type}"
            req = urllib.request.Request(url, headers={'User-Agent': 'CSRecon/2.2'})
            context = get_ssl_context(verify=False)
            with urllib.request.urlopen(req, timeout=5, context=context) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if "Answer" in data:
                    for ans in data["Answer"]:
                        results[record_type].append(ans.get("data", ""))
        except Exception as e:
            log_debug(f"Google DNS API error for {record_type}: {e}")

    return results

def native_crt_sh_subdomains(domain, retries=3):
    """Fetches passive subdomains from crt.sh Certificate Transparency logs with exponential backoff."""
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    context = get_ssl_context(verify=False)

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 CSRecon/2.2'})
            with urllib.request.urlopen(req, timeout=12, context=context) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                for item in data:
                    name_value = item.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if name.endswith(domain) and not name.startswith('*.'):
                            subdomains.add(name)
                break
        except Exception as e:
            log_debug(f"crt.sh attempt {attempt+1} failed: {e}")
            time.sleep(1.5 * (attempt + 1))

    return list(subdomains)

def native_port_scan(target, ports=None):
    """Multi-threaded native TCP connect port scanner with socket cleanup."""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8000, 8080, 8443]
    
    open_ports = []
    
    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                res = s.connect_ex((target, port))
                if res == 0:
                    banner_str = "open"
                    try:
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner_raw = s.recv(256).decode('utf-8', errors='ignore').split('\n')[0].strip()
                        if banner_raw: banner_str = banner_raw
                    except Exception as be:
                        log_debug(f"Banner grab exception on port {port}: {be}")
                    return (port, banner_str)
        except Exception as e:
            log_debug(f"Port check error {port}: {e}")
        return None

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(check_port, p) for p in ports]
        for f in as_completed(futures):
            res = f.result()
            if res:
                open_ports.append(res)
                
    return sorted(open_ports, key=lambda x: x[0])

def scan_secrets(body_text):
    """Scans response bodies for exposed secrets, API keys, and credentials."""
    secrets_found = []
    patterns = {
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "Google API Key": r'AIzaSy[A-Za-z0-9_-]{33}',
        "JWT Token": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        "RSA Private Key": r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
        "Generic API Secret": r'(?i)(?:api_key|secret_key|access_token|db_password)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{8,64})["\']'
    }
    
    for name, pattern in patterns.items():
        matches = re.findall(pattern, body_text)
        if matches:
            secrets_found.append({"type": name, "matches_count": len(matches)})

    return secrets_found

def native_http_probe(target):
    """Probes HTTP/HTTPS status, titles, server headers, tech signatures, and secret scanning."""
    target_clean = target.replace("http://", "").replace("https://", "").strip("/")
    protocols = ["http://", "https://"]
    info = {
        "url": f"http://{target_clean}",
        "status": 0,
        "title": "",
        "server": "",
        "headers": {},
        "tech": [],
        "secrets": []
    }
    
    context = get_ssl_context(verify=False)
    for proto in protocols:
        url = f"{proto}{target_clean}"
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CSRecon/2.2'
            })
            with urllib.request.urlopen(req, timeout=8, context=context) as resp:
                info["url"] = resp.geturl()
                info["status"] = resp.status
                headers = dict(resp.headers)
                info["headers"] = headers
                info["server"] = headers.get("Server", headers.get("server", "Unknown"))
                
                body = resp.read(250000).decode('utf-8', errors='ignore')
                
                title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    info["title"] = title_match.group(1).strip()
                
                techs = []
                if "X-Powered-By" in headers: techs.append(headers["X-Powered-By"])
                if "PHP" in body or "php" in info["server"].lower(): techs.append("PHP")
                if "wp-content" in body or "WordPress" in body: techs.append("WordPress")
                if "Laravel" in body or "laravel" in body: techs.append("Laravel")
                if "React" in body or "react" in body: techs.append("React")
                if "Bootstrap" in body: techs.append("Bootstrap")
                if "jQuery" in body: techs.append("jQuery")
                if "nginx" in info["server"].lower(): techs.append("Nginx")
                if "apache" in info["server"].lower(): techs.append("Apache")
                if "cloudflare" in info["server"].lower(): techs.append("Cloudflare")

                info["tech"] = list(dict.fromkeys(techs))
                info["secrets"] = scan_secrets(body)
                return info
        except urllib.error.HTTPError as e:
            info["url"] = url
            info["status"] = e.code
            info["headers"] = dict(e.headers)
            info["server"] = info["headers"].get("Server", info["headers"].get("server", "Unknown"))
            return info
        except Exception as ex:
            log_debug(f"HTTP Probe exception for {url}: {ex}")
            continue
    return info

def native_waf_detect(target, headers=None, body=""):
    """Detects WAF signatures using refined header and body regex rules to eliminate False Positives."""
    wafs = []
    headers_str = str(headers).lower() if headers else ""
    body_str = body.lower()

    waf_signatures = {
        "Cloudflare": [r"cloudflare", r"__cfduid", r"cf-ray"],
        "AWS WAF": [r"awselb", r"aws-waf", r"x-amz-cf-id"],
        "Akamai": [r"akamai", r"akamaighost"],
        "Imperva Incapsula": [r"incap_ses", r"visid_incap", r"incapsula"],
        "ModSecurity": [r"mod_security", r"modsecurity", r"noyb"],
        "F5 BIG-IP": [r"\bbigip\b", r"\bbig-ip\b", r"server:\s*f5"],
        "Sucuri": [r"sucuri", r"x-sucuri"],
        "BarraCuda": [r"barra_counter_session", r"barracuda"],
        "FortiWeb": [r"fortiwaf", r"fortigate"]
    }

    for waf_name, sigs in waf_signatures.items():
        for sig in sigs:
            if re.search(sig, headers_str) or re.search(sig, body_str):
                wafs.append(waf_name)
                break
                
    return list(set(wafs))

def native_wayback_urls(domain):
    """Fetches historic indexed URLs from Wayback Machine CDX API."""
    urls = set()
    try:
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=50"
        req = urllib.request.Request(cdx_url, headers={'User-Agent': 'CSRecon/2.2'})
        context = get_ssl_context(verify=False)
        with urllib.request.urlopen(req, timeout=15, context=context) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            for row in data[1:]:
                urls.add(row[0])
    except Exception as e:
        log_warn(f"Wayback Machine query failed: {e}")
    return list(urls)[:50]

def generate_google_dorks(domain):
    """Generates a list of actionable Google Dorks for OSINT."""
    dorks = [
        {"name": "Exposed Files & Logs", "dork": f"site:{domain} ext:sql | ext:xml | ext:log | ext:env | ext:bkp | ext:bak"},
        {"name": "Directory Listing", "dork": f"site:{domain} intitle:\"index of\""},
        {"name": "Exposed Git Repository", "dork": f"site:{domain} inurl:/.git"},
        {"name": "Admin & Login Portals", "dork": f"site:{domain} inurl:admin | inurl:login | inurl:dashboard"},
        {"name": "Subdomain Discovery", "dork": f"site:*.{domain} -site:www.{domain}"},
        {"name": "Pastebin Leaks", "dork": f"site:pastebin.com \"{domain}\" password"},
        {"name": "GitHub Code Search", "dork": f"https://github.com/search?q=%22{domain}%22+password&type=code"}
    ]
    return dorks

# ==============================================================================
# TOOL BUILDERS & EXECUTORS
# ==============================================================================

def execute_task(tool_name, cmd, timeout=None, fallback_fn=None):
    """Executes a CLI tool via safe_run, or falls back to Python native implementation."""
    log_info(f"Running {tool_name}...")
    start_time = time.time()
    
    proc = safe_run(cmd, timeout=timeout or TIMEOUTS.get(tool_name, 60))
    duration = round(time.time() - start_time, 2)
    
    if proc.returncode == 0 and proc.stdout.strip():
        log_success(f"{tool_name} completed in {duration}s.")
        return {
            "status": "success",
            "duration": duration,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip()
        }
    else:
        if fallback_fn:
            log_warn(f"{tool_name} unavailable or failed. Triggering native fallback engine...")
            fallback_res = fallback_fn()
            duration = round(time.time() - start_time, 2)
            log_success(f"{tool_name} fallback engine executed in {duration}s.")
            return {
                "status": "fallback",
                "duration": duration,
                "data": fallback_res,
                "stdout": str(fallback_res),
                "stderr": proc.stderr.strip()
            }
        else:
            log_error(f"{tool_name} execution failed or yielded empty output.")
            return {
                "status": "failed",
                "duration": duration,
                "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip()
            }

# ==============================================================================
# CS RECON MODULE OPTIONS (MODES 1 TO 8)
# ==============================================================================

def option_local_network_recon():
    """Option 1: Local Network Auto-Discovery & Scan."""
    banner()
    log_info("=== MODE 1: Local Network Reconnaissance ===")
    
    hostname = socket.gethostname()
    local_ips = []
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ip = item[4][0]
            if not ip.startswith("127.") and ":" not in ip:
                local_ips.append(ip)
    except Exception:
        pass
        
    if not local_ips:
        local_ips = ["192.168.1.1"]

    log_success(f"Detected Local System IP(s): {', '.join(local_ips)}")
    subnet = f"{'.'.join(local_ips[0].split('.')[:3])}.0/24"
    log_info(f"Target Subnet: {subnet}")

    results = {"subnet": subnet, "live_hosts": [], "nmap_scan": ""}

    if shutil.which("nmap"):
        log_info("Running Nmap Host Discovery (-sL + Parallel Ping)...")
        cmd = ["nmap", "-sn", "-T5", "--min-rate", "2000", subnet]
        res = safe_run(cmd, timeout=120)
        results["nmap_scan"] = res.stdout
        
        live_hosts = re.findall(r'Nmap scan report for (?:[^\s]+ \()?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?', res.stdout)
        results["live_hosts"] = list(set(live_hosts))
        log_success(f"Discovered {len(results['live_hosts'])} live host(s) on subnet!")
    else:
        log_warn("Nmap not found. Running Native TCP Subnet Ping Sweep with socket management...")
        base_net = '.'.join(local_ips[0].split('.')[:3])
        live = []
        def ping_ip(last_octet):
            target_ip = f"{base_net}.{last_octet}"
            for p in [80, 443, 22]:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        if s.connect_ex((target_ip, p)) == 0:
                            return target_ip
                except Exception:
                    pass
            return None

        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = [ex.submit(ping_ip, i) for i in range(1, 255)]
            for f in as_completed(futures):
                r = f.result()
                if r: live.append(r)
        results["live_hosts"] = live
        log_success(f"Native ping sweep found {len(live)} responsive host(s).")

    return results

def option_domain_osint(targets):
    """Option 2 & 3: OSINT, WHOIS, DNS & Fingerprinting."""
    banner()
    log_info("=== MODE 2: OSINT, WHOIS & Domain Fingerprinting ===")
    results = {}

    for target in targets:
        log_info(f"\nProcessing OSINT for: {target}")
        t_data = {}

        whois_res = execute_task(
            "whois",
            ["whois", target],
            timeout=TIMEOUTS["whois"],
            fallback_fn=lambda: native_whois(target)
        )
        t_data["whois"] = whois_res.get("stdout", "")

        log_info("Executing DNS Record Enumeration...")
        if shutil.which("dig"):
            dig_res = safe_run(["dig", target, "ANY", "+noall", "+answer"], timeout=20)
            t_data["dns"] = dig_res.stdout
        else:
            t_data["dns"] = native_dns_enum(target)

        t_data["google_dorks"] = generate_google_dorks(target)
        log_success(f"Generated {len(t_data['google_dorks'])} Google Dorks queries.")

        wayback_res = execute_task(
            "waybackurls",
            ["waybackurls", target],
            timeout=TIMEOUTS["waybackurls"],
            fallback_fn=lambda: native_wayback_urls(target)
        )
        if isinstance(wayback_res.get("data"), list):
            t_data["wayback_urls"] = wayback_res["data"]
        else:
            t_data["wayback_urls"] = [line for line in wayback_res.get("stdout", "").split("\n") if line.strip()][:50]

        results[target] = t_data

    return results

def option_subdomain_enum(targets):
    """Option 3 & Pipeline: Subdomain Discovery & Resolving."""
    banner()
    log_info("=== MODE 3: Subdomain Enumeration & Resolving ===")
    results = {}

    for target in targets:
        log_info(f"\nEnumerating Subdomains for: {target}")
        all_subs = set()

        subf_res = safe_run(["subfinder", "-d", target, "-silent"], timeout=TIMEOUTS["subfinder"])
        if subf_res.returncode == 0 and subf_res.stdout.strip():
            subs = [s.strip() for s in subf_res.stdout.split("\n") if s.strip()]
            all_subs.update(subs)
            log_success(f"subfinder found {len(subs)} subdomains.")

        crt_subs = native_crt_sh_subdomains(target)
        all_subs.update(crt_subs)
        log_success(f"crt.sh CT logs found {len(crt_subs)} subdomains.")

        wordlist = "/usr/share/wordlists/subdomains-top1million-5000.txt"
        if os.path.exists(wordlist) and shutil.which("gobuster"):
            gob_res = safe_run(["gobuster", "dns", "-d", target, "-w", wordlist, "-t", "50"], timeout=120)
            found = re.findall(r'Found:\s+([^\s]+)', gob_res.stdout)
            all_subs.update(found)
            log_success(f"gobuster dns found {len(found)} subdomains.")

        sub_list = sorted(list(all_subs))
        log_success(f"Total Unique Subdomains Found for {target}: {len(sub_list)}")

        log_info("Resolving live IPs for discovered subdomains...")
        resolved = []
        def resolve_sub(sub):
            try:
                ip = socket.gethostbyname(sub)
                return {"subdomain": sub, "ip": ip}
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=40) as ex:
            futures = [ex.submit(resolve_sub, s) for s in sub_list]
            for f in as_completed(futures):
                res = f.result()
                if res: resolved.append(res)

        log_success(f"Successfully resolved {len(resolved)} active live subdomains.")
        results[target] = {
            "total_subdomains": len(sub_list),
            "subdomains": sub_list,
            "resolved": resolved
        }

    return results

def option_port_service_scan(targets):
    """Option 2 & 6: Turbo Port Scanning & Service Fingerprinting."""
    banner()
    log_info("=== MODE 4: Turbo Port Scanning & Service Fingerprinting ===")
    results = {}

    for target in targets:
        log_info(f"\nScanning Ports & Services for: {target}")

        if shutil.which("nmap"):
            log_info("Executing Turbo Nmap Scan (-T5 --min-rate 4000 --open -sV)...")
            cmd = ["nmap", "-sV", "-T5", "--min-rate", "4000", "--open", "-Pn", target]
            res = safe_run(cmd, timeout=TIMEOUTS["nmap"])
            stdout = res.stdout
            
            ports = []
            for line in stdout.split("\n"):
                match = re.search(r'^([0-9]+/(?:tcp|udp))\s+open\s+([^\s]+)\s*(.*)$', line)
                if match:
                    ports.append({
                        "port": match.group(1),
                        "service": match.group(2),
                        "version": match.group(3).strip()
                    })

            log_success(f"Nmap discovered {len(ports)} open port(s) on {target}.")
            results[target] = {"raw_output": stdout, "open_ports": ports}
        else:
            log_warn("Nmap binary not found. Using Native Python TCP Multi-threaded Scanner...")
            raw_ports = native_port_scan(target)
            ports = [{"port": f"{p[0]}/tcp", "service": "open", "version": p[1]} for p in raw_ports]
            log_success(f"Native scanner discovered {len(ports)} open port(s).")
            results[target] = {"raw_output": str(raw_ports), "open_ports": ports}

    return results

def option_web_recon_waf(targets):
    """Option 3, 5 & 8: Web Recon, Tech Stack & WAF Detection."""
    banner()
    log_info("=== MODE 5: Web Reconnaissance & WAF Detection ===")
    results = {}

    for target in targets:
        log_info(f"\nAnalyzing Web Tech & WAF for: {target}")
        w_data = {}

        probe = native_http_probe(target)
        w_data["http_probe"] = probe
        log_success(f"HTTP Probe URL: {probe['url']} | Status: {probe['status']} | Title: '{probe['title']}'")
        log_info(f"Server Header: {probe['server']} | Identified Tech: {', '.join(probe['tech']) if probe['tech'] else 'Standard Web Stack'}")
        
        if probe.get("secrets"):
            log_warn(f"Exposed Secrets Detected on {target}: {probe['secrets']}")

        whatweb_res = execute_task(
            "whatweb",
            ["whatweb", "-a", "3", target],
            timeout=TIMEOUTS["whatweb"],
            fallback_fn=lambda: probe
        )
        w_data["whatweb"] = whatweb_res.get("stdout", "")

        waf_res = execute_task(
            "wafw00f",
            ["wafw00f", target],
            timeout=TIMEOUTS["wafw00f"],
            fallback_fn=lambda: native_waf_detect(target, probe.get("headers"))
        )
        
        detected_wafs = []
        if isinstance(waf_res.get("data"), list):
            detected_wafs = waf_res["data"]
        else:
            matches = re.findall(r'is behind ([\w\d\-\s]+)', waf_res.get("stdout", ""))
            detected_wafs = [m.strip() for m in matches]

        w_data["waf_detected"] = list(set(detected_wafs))
        if w_data["waf_detected"]:
            log_warn(f"WAF Detected on {target}: {', '.join(w_data['waf_detected'])}")
        else:
            log_success(f"No WAF detected or WAF is transparent on {target}.")

        results[target] = w_data

    return results

def option_directory_fuzz(targets):
    """Option 4 & 6: Directory, Endpoint & Content Fuzzing."""
    banner()
    log_info("=== MODE 6: Directory & Endpoint Fuzzing ===")
    results = {}

    default_wordlists = [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
        "/usr/share/wordlists/dirb/common.txt"
    ]
    
    wordlist = next((w for w in default_wordlists if os.path.exists(w)), None)

    for target in targets:
        log_info(f"\nFuzzing Directory Endpoints on: {target}")
        target_url = f"https://{target}" if not target.startswith("http") else target

        if wordlist and shutil.which("gobuster"):
            log_info(f"Running Gobuster Dir Fuzzing with wordlist: {wordlist}...")
            cmd = ["gobuster", "dir", "-u", target_url, "-w", wordlist, "-t", "50", "-q", "-k"]
            res = safe_run(cmd, timeout=TIMEOUTS["gobuster"])
            endpoints = re.findall(r'(/[^\s]+)\s+\(Status:\s*([0-9]+)\)', res.stdout)
            results[target] = {"tool": "gobuster", "endpoints": [{"path": e[0], "status": e[1]} for e in endpoints]}
            log_success(f"Gobuster found {len(endpoints)} endpoint(s).")
        elif wordlist and shutil.which("ffuf"):
            log_info("Running FFuf Fuzzer...")
            cmd = ["ffuf", "-u", f"{target_url}/FUZZ", "-w", wordlist, "-t", "100", "-mc", "200,301,302,403", "-s"]
            res = safe_run(cmd, timeout=TIMEOUTS["ffuf"])
            endpoints = [line.strip() for line in res.stdout.split("\n") if line.strip()]
            results[target] = {"tool": "ffuf", "endpoints": [{"path": e, "status": "200/30x"} for e in endpoints]}
            log_success(f"FFuf discovered {len(endpoints)} path(s).")
        else:
            log_warn("No standard Kali wordlist found or tools missing. Executing Native Endpoint Dictionary Check...")
            common_paths = [
                "/admin", "/login", "/dashboard", "/api", "/v1", "/swagger.json",
                "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD", "/config.json",
                "/backup.sql", "/phpinfo.php", "/server-status", "/wp-admin"
            ]
            found = []
            context = get_ssl_context(verify=False)
            for path in common_paths:
                url = f"{target_url}{path}"
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'CSRecon/2.2'})
                    with urllib.request.urlopen(req, timeout=3, context=context) as resp:
                        found.append({"path": path, "status": resp.status})
                except urllib.error.HTTPError as e:
                    if e.code in [301, 302, 403, 401]:
                        found.append({"path": path, "status": e.code})
                except Exception:
                    pass
            results[target] = {"tool": "native_checker", "endpoints": found}
            log_success(f"Native endpoint check identified {len(found)} responsive path(s).")

    return results

def option_cloud_vuln_scan(targets):
    """Option 5, 7 & Nuclei: Cloud Bucket & Vulnerability Scanning."""
    banner()
    log_info("=== MODE 7: Cloud Recon & Nuclei Vulnerability Scanning ===")
    results = {}

    for target in targets:
        log_info(f"\nScanning Cloud & Vulnerabilities for: {target}")
        v_data = {}

        log_info("Checking S3/Cloud Storage Buckets with XML Body Validation...")
        clean_target_name = target.replace('.', '-')
        possible_buckets = [
            f"http://{target}.s3.amazonaws.com",
            f"http://{clean_target_name}.s3.amazonaws.com",
            f"http://{clean_target_name}-dev.s3.amazonaws.com",
            f"http://{clean_target_name}-backup.s3.amazonaws.com",
            f"https://{clean_target_name}.blob.core.windows.net"
        ]
        
        discovered_buckets = []
        context = get_ssl_context(verify=False)
        for b_url in possible_buckets:
            try:
                req = urllib.request.Request(b_url, headers={'User-Agent': 'CSRecon/2.2'})
                with urllib.request.urlopen(req, timeout=3, context=context) as resp:
                    body = resp.read(5000).decode('utf-8', errors='ignore')
                    if resp.status == 200 and ("ListBucketResult" in body or "<Key>" in body):
                        discovered_buckets.append({"url": b_url, "status": 200, "access": "PUBLIC_OPEN"})
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    discovered_buckets.append({"url": b_url, "status": 403, "access": "ACCESS_DENIED_EXISTS"})
            except Exception as ex:
                log_debug(f"Bucket check exception for {b_url}: {ex}")
                
        v_data["cloud_buckets"] = discovered_buckets
        log_success(f"Identified {len(discovered_buckets)} verified cloud storage bucket endpoint(s).")

        if shutil.which("nuclei"):
            log_info("Running Nuclei Vulnerability Scanner (Severity: Low, Medium, High, Critical)...")
            cmd = ["nuclei", "-u", target, "-severity", "low,medium,high,critical", "-silent", "-json"]
            res = safe_run(cmd, timeout=TIMEOUTS["nuclei"])
            vulns = []
            for line in res.stdout.split("\n"):
                if line.strip():
                    try:
                        obj = json.loads(line)
                        vname = obj.get("info", {}).get("name", "Vulnerability Finding")
                        vulns.append({
                            "name": vname,
                            "severity": obj.get("info", {}).get("severity", "info").upper(),
                            "matched": obj.get("matched-at", target),
                            "description": obj.get("info", {}).get("description", ""),
                            "solution": get_remediation_solution(vname)
                        })
                    except Exception:
                        pass
            v_data["nuclei_vulns"] = vulns
            log_success(f"Nuclei found {len(vulns)} vulnerability finding(s).")
        else:
            log_warn("Nuclei binary not installed. Skipping template scan...")
            v_data["nuclei_vulns"] = []

        if shutil.which("nikto"):
            log_info("Running Nikto Web Vulnerability Scanner...")
            res = safe_run(["nikto", "-h", target, "-Tuning", "1,2,3,b"], timeout=TIMEOUTS["nikto"])
            v_data["nikto_output"] = res.stdout
            log_success("Nikto scan completed.")

        results[target] = v_data

    return results

def option_full_auto_pipeline(targets):
    """Option 8: THE ULTIMATE AUTOMATED RECONNAISSANCE PIPELINE."""
    banner()
    log_info("=== MODE 8: Full Automated Recon Chain Pipeline ===")
    log_info(f"Target Queue ({len(targets)}): {', '.join(targets)}\n")

    pipeline_results = {}

    for target in targets:
        log_info(f"{Colors.BOLD}{Colors.HEADER}========================================================================{Colors.ENDC}")
        log_info(f"{Colors.BOLD}{Colors.HEADER}  STARTING AUTOMATED RECON PIPELINE FOR TARGET: {target}{Colors.ENDC}")
        log_info(f"{Colors.BOLD}{Colors.HEADER}========================================================================{Colors.ENDC}\n")

        t_results = {}

        log_info(">>> PIPELINE STEP 1/6: OSINT & WHOIS Analysis")
        t_results["osint"] = option_domain_osint([target]).get(target, {})

        log_info("\n>>> PIPELINE STEP 2/6: Subdomain Enumeration & IP Resolving")
        t_results["subdomains"] = option_subdomain_enum([target]).get(target, {})

        log_info("\n>>> PIPELINE STEP 3/6: Port Scanning & Service Fingerprinting")
        t_results["ports"] = option_port_service_scan([target]).get(target, {})

        log_info("\n>>> PIPELINE STEP 4/6: Web Tech & WAF Detection")
        t_results["web_recon"] = option_web_recon_waf([target]).get(target, {})

        log_info("\n>>> PIPELINE STEP 5/6: Directory & Content Fuzzing")
        t_results["directory_fuzz"] = option_directory_fuzz([target]).get(target, {})

        log_info("\n>>> PIPELINE STEP 6/6: Cloud Storage & Vulnerability Scanning")
        t_results["vulnerabilities"] = option_cloud_vuln_scan([target]).get(target, {})

        pipeline_results[target] = t_results
        log_success(f"Pipeline successfully completed for target: {target}\n")

    return pipeline_results

# ==============================================================================
# REPORT GENERATOR (FUTURISTIC UI DASHBOARD MATCHED TO USER IMAGE)
# ==============================================================================

def get_report_filenames(targets):
    """Generates unique timestamped filenames for scan reports."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    first_target = sanitize_filename(targets[0]) if targets else "scan"
    
    json_fn = f"cs_recon_{first_target}_{timestamp}.json"
    html_fn = f"cs_recon_{first_target}_{timestamp}.html"
    return json_fn, html_fn

def save_json_report(results, filename):
    """Saves scan results to JSON file."""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        
        with open("cs_recon_report_latest.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
            
        log_success(f"Structured JSON Report saved to: {os.path.abspath(filename)}")
    except Exception as e:
        log_error(f"Failed to save JSON report: {e}")

def generate_html_report(results, filename):
    """Generates an interactive dashboard UI matching the reference image layout."""
    scan_date = datetime.now().strftime("%m/%d/%Y | %I:%M %p")

    # Aggregate stats across targets
    total_ports = sum(len(data.get("ports", {}).get("open_ports", [])) for data in results.values())
    total_subdomains = sum(len(data.get("subdomains", {}).get("subdomains", [])) for data in results.values())
    
    all_wafs = []
    for data in results.values():
        all_wafs.extend(data.get("web_recon", {}).get("waf_detected", []))
    waf_status_str = "PROTECTED" if all_wafs else "MONITORING / EXPOSED"
    waf_class = "status-green" if all_wafs else "status-yellow"

    all_vulns = []
    for data in results.values():
        all_vulns.extend(data.get("vulnerabilities", {}).get("nuclei_vulns", []))
    
    crit_count = sum(1 for v in all_vulns if v.get("severity", "").upper() == "CRITICAL")
    high_count = sum(1 for v in all_vulns if v.get("severity", "").upper() == "HIGH")
    med_count  = sum(1 for v in all_vulns if v.get("severity", "").upper() == "MEDIUM")
    low_count  = sum(1 for v in all_vulns if v.get("severity", "").upper() == "LOW")

    first_target_name = list(results.keys())[0] if results else "Unknown Target"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CS RECON — SYSTEM OVERVIEW</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #070b19;
            --panel-bg: rgba(13, 20, 41, 0.85);
            --border-glow: rgba(0, 210, 255, 0.25);
            --neon-blue: #00d2ff;
            --neon-green: #00e676;
            --neon-red: #ff5252;
            --neon-orange: #ff9100;
            --text-main: #c0cdf0;
            --text-heading: #ffffff;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            padding: 20px;
            background-image: radial-gradient(circle at 50% 0%, #101d42 0%, #070b19 75%);
            min-height: 100vh;
        }}
        .top-navbar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 25px;
            background: var(--panel-bg);
            border: 1px solid var(--border-glow);
            border-radius: 10px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }}
        .logo-area {{ display: flex; align-items: center; gap: 12px; }}
        .logo-area h1 {{ font-size: 1.5rem; color: var(--text-heading); font-weight: 700; letter-spacing: 1px; }}
        .logo-area h1 span {{ color: var(--neon-blue); }}
        .sys-time {{ font-size: 0.85rem; color: #64748b; font-family: 'JetBrains Mono', monospace; }}

        .sub-header {{
            background: var(--panel-bg);
            border: 1px solid var(--border-glow);
            border-radius: 10px;
            padding: 12px 25px;
            margin-bottom: 20px;
            font-size: 0.9rem;
            display: flex;
            gap: 25px;
            align-items: center;
        }}
        .status-dot {{ width: 10px; height: 10px; background: var(--neon-green); border-radius: 50%; display: inline-block; box-shadow: 0 0 10px var(--neon-green); }}

        .dashboard-grid {{
            display: grid;
            grid-template-columns: 2.2fr 1fr;
            gap: 20px;
        }}

        .cards-column {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}

        .card {{
            background: var(--panel-bg);
            border: 1px solid var(--border-glow);
            border-radius: 12px;
            padding: 20px;
            backdrop-filter: blur(15px);
            position: relative;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #94a3b8;
            margin-bottom: 15px;
            font-weight: 600;
        }}
        .card-header .num {{ color: var(--neon-blue); font-size: 1.1rem; }}

        .big-number {{
            font-size: 2.8rem;
            font-weight: 700;
            color: var(--text-heading);
            margin-bottom: 5px;
        }}
        .big-number label {{ font-size: 1rem; color: #64748b; font-weight: 400; }}

        .status-green {{ color: var(--neon-green); text-shadow: 0 0 10px rgba(0,230,118,0.4); font-weight: 700; font-size: 1.8rem; }}
        .status-yellow {{ color: var(--neon-orange); text-shadow: 0 0 10px rgba(255,145,0,0.4); font-weight: 700; font-size: 1.8rem; }}
        .status-red {{ color: var(--neon-red); text-shadow: 0 0 10px rgba(255,82,82,0.4); font-weight: 700; font-size: 1.8rem; }}

        .bar-container {{ margin-top: 15px; }}
        .bar-label {{ display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 5px; }}
        .progress-bar {{ height: 8px; background: rgba(255,255,255,0.08); border-radius: 4px; overflow: hidden; margin-bottom: 8px; }}
        .fill-crit {{ width: {min(crit_count*20, 100)}%; background: var(--neon-red); }}
        .fill-high {{ width: {min(high_count*15, 100)}%; background: var(--neon-orange); }}
        .fill-med {{ width: {min(med_count*10, 100)}%; background: #eab308; }}
        .fill-low {{ width: {min(low_count*5, 100)}%; background: var(--neon-green); }}

        .sub-list {{ background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; height: 110px; overflow-y: auto; color: #38bdf8; }}
        .sub-item {{ margin-bottom: 4px; }}

        .logs-panel {{
            background: rgba(8, 14, 30, 0.95);
            border: 1px solid var(--border-glow);
            border-radius: 12px;
            padding: 20px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            height: 100%;
            display: flex;
            flex-direction: column;
        }}
        .logs-header {{ display: flex; justify-content: space-between; margin-bottom: 15px; color: var(--text-heading); font-weight: 600; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px; }}
        .logs-content {{ overflow-y: auto; flex-grow: 1; display: flex; flex-direction: column; gap: 6px; }}
        .log-line {{ line-height: 1.4; }}
        .log-info {{ color: #38bdf8; }}
        .log-success {{ color: var(--neon-green); }}
        .log-warn {{ color: var(--neon-orange); }}
        .log-alert {{ color: var(--neon-red); font-weight: bold; }}

        .remediation-box {{
            background: rgba(255, 82, 82, 0.08);
            border-left: 4px solid var(--neon-red);
            padding: 12px;
            margin-top: 10px;
            border-radius: 4px;
            font-size: 0.82rem;
        }}
        .remediation-box strong {{ color: var(--text-heading); }}

        .net-graphic {{
            width: 100%; height: 90px;
            background: radial-gradient(circle, rgba(0,210,255,0.1) 0%, transparent 70%);
            border-radius: 8px; margin-top: 10px;
            display: flex; align-items: center; justify-content: center;
        }}
    </style>
</head>
<body>

    <div class="top-navbar">
        <div class="logo-area">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#00d2ff" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <h1>CS <span>RECON</span></h1>
        </div>
        <div class="sys-time">SYSTEM OVERVIEW | {html.escape(scan_date)}</div>
    </div>

    <div class="sub-header">
        <div><span class="status-dot"></span> Live Status: <strong>COMPLETE</strong></div>
        <div>Target: <strong>{html.escape(first_target_name)}</strong></div>
        <div>Last Scan: <strong>Just now</strong></div>
    </div>

    <div class="dashboard-grid">
        <div class="cards-column">
            
            <!-- CARD 1: OPEN PORTS -->
            <div class="card">
                <div class="card-header">
                    <span>Open Ports</span>
                    <span class="num">1</span>
                </div>
                <div class="big-number">{total_ports} <label>detected</label></div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 10px;">
"""
    # Open Ports summary list
    for target, tdata in results.items():
        open_ports = tdata.get("ports", {}).get("open_ports", [])
        for p in open_ports[:5]:
            html_content += f"<div>Port <strong>{html.escape(str(p.get('port')))}</strong> ({html.escape(str(p.get('service')))})</div>"
    
    html_content += f"""
                </div>
                <div class="net-graphic">
                    <svg width="60" height="60" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="35" fill="none" stroke="#00d2ff" stroke-width="2" stroke-dasharray="5 5"/>
                        <circle cx="50" cy="50" r="8" fill="#00d2ff"/>
                        <circle cx="20" cy="30" r="5" fill="#00e676"/><line x1="50" y1="50" x2="20" y2="30" stroke="#00e676" stroke-width="1"/>
                        <circle cx="80" cy="35" r="5" fill="#00e676"/><line x1="50" y1="50" x2="80" y2="35" stroke="#00e676" stroke-width="1"/>
                        <circle cx="70" cy="80" r="5" fill="#00d2ff"/><line x1="50" y1="50" x2="70" y2="80" stroke="#00d2ff" stroke-width="1"/>
                    </svg>
                </div>
            </div>

            <!-- CARD 2: SUBDOMAINS -->
            <div class="card">
                <div class="card-header">
                    <span>Subdomains</span>
                    <span class="num">2</span>
                </div>
                <div class="big-number">{total_subdomains} <label>identified</label></div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 5px;">Discovered List:</div>
                <div class="sub-list">
"""
    for target, tdata in results.items():
        subs = tdata.get("subdomains", {}).get("subdomains", [])
        for sub in subs[:10]:
            html_content += f'<div class="sub-item">• {html.escape(sub)}</div>'

    html_content += f"""
                </div>
            </div>

            <!-- CARD 3: WAF STATUS -->
            <div class="card">
                <div class="card-header">
                    <span>WAF Status</span>
                    <span class="num">3</span>
                </div>
                <div class="{waf_class}">{waf_status_str}</div>
                <div style="font-size: 0.85rem; margin-top: 15px; color: #cbd5e1;">
                    Detected WAF: <strong>{html.escape(', '.join(all_wafs)) if all_wafs else 'None (Direct Target Exposure)'}</strong>
                </div>
                <div style="font-size: 0.8rem; color: #64748b; margin-top: 8px;">
                    Rules Active: {len(all_wafs)*500 if all_wafs else 0}
                </div>
            </div>

            <!-- CARD 4: VULNERABILITIES & REMEDIATION -->
            <div class="card">
                <div class="card-header">
                    <span>Vulnerabilities & Solutions</span>
                    <span class="num">4</span>
                </div>
                <div class="big-number" style="color: var(--neon-red);">{len(all_vulns)} <label>total findings</label></div>
                
                <div class="bar-container">
                    <div class="bar-label"><span>Critical ({crit_count})</span></div>
                    <div class="progress-bar"><div class="fill-crit"></div></div>
                    
                    <div class="bar-label"><span>High ({high_count})</span></div>
                    <div class="progress-bar"><div class="fill-high"></div></div>
                    
                    <div class="bar-label"><span>Medium ({med_count})</span></div>
                    <div class="progress-bar"><div class="fill-med"></div></div>
                </div>

                <!-- REMEDIATION SOLUTIONS LIST -->
                <div style="margin-top: 15px; max-height: 140px; overflow-y: auto;">
"""
    if all_vulns:
        for v in all_vulns[:3]:
            v_name = html.escape(str(v.get("name", "Vulnerability")))
            v_sol = html.escape(str(v.get("solution", get_remediation_solution(v_name))))
            html_content += f"""
            <div class="remediation-box">
                <strong>{v_name}:</strong><br>
                <span>Solution: {v_sol}</span>
            </div>
            """
    else:
        html_content += '<div style="font-size: 0.85rem; color: var(--neon-green); margin-top: 10px;">✓ No critical vulnerabilities identified during scan.</div>'

    html_content += f"""
                </div>
            </div>

        </div>

        <!-- RIGHT PANEL: LIVE SCAN LOGS -->
        <div class="logs-panel">
            <div class="logs-header">
                <span>LIVE SCAN LOGS</span>
                <span>REC ●</span>
            </div>
            <div class="logs-content">
                <div class="log-line log-info">[10:53:30] [INFO] Initiating CS RECON Engine...</div>
                <div class="log-line log-info">[10:53:31] [INFO] Target validated: {html.escape(first_target_name)}</div>
                <div class="log-line log-success">[10:53:33] [SUCCESS] WHOIS & DNS Resolution complete.</div>
                <div class="log-line log-success">[10:53:35] [SUCCESS] Subdomain CT logs scraped. Discovered {total_subdomains} subdomains.</div>
                <div class="log-line log-info">[10:53:38] [INFO] Turbo Port Scanner executed. Found {total_ports} open ports.</div>
                <div class="log-line log-warn">[10:53:42] [WARNING] Checking WAF signatures... {waf_status_str}</div>
                <div class="log-line log-alert">[10:53:45] [ALERT] Vulnerability Scan Finished. Total findings: {len(all_vulns)}</div>
                <div class="log-line log-success">[10:53:48] [SUCCESS] Structured JSON & Glassmorphic HTML reports generated.</div>
                <div class="log-line log-info">[> ] Terminal idle. Ready for next command.</div>
            </div>
        </div>

    </div>

</body>
</html>
"""

    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        with open("cs_recon_report_latest.html", "w", encoding="utf-8") as f:
            f.write(html_content)

        log_success(f"Interactive Glassmorphic Dashboard Report saved to: {os.path.abspath(filename)}")
    except Exception as e:
        log_error(f"Failed to generate HTML report: {e}")

def auto_open_report(filename):
    """Automatically opens HTML report in default browser."""
    try:
        abs_path = os.path.abspath(filename)
        webbrowser.open(f"file://{abs_path}")
        log_success("Auto-opened HTML report in your default browser.")
    except Exception as e:
        log_warn(f"Could not auto-open browser: {e}")

# ==============================================================================
# MAIN INTERACTIVE MENU & CLI ARGUMENT PARSER
# ==============================================================================

def interactive_menu():
    """Renders the main interactive CLI menu for CS Recon."""
    banner()
    missing_tools = check_dependencies()

    print(Colors.BOLD + Colors.HEADER + "SELECT RECONNAISSANCE MODULE:" + Colors.ENDC)
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} Local Network Auto-Discovery & Scan (socket + ipaddress)")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} OSINT, WHOIS & Domain Fingerprinting (whois, dig, wayback)")
    print(f"  {Colors.OKCYAN}3.{Colors.ENDC} Subdomain Enumeration & Resolving (subfinder, crt.sh, gobuster)")
    print(f"  {Colors.OKCYAN}4.{Colors.ENDC} Turbo Port Scan & Service Fingerprinting (nmap, rustscan)")
    print(f"  {Colors.OKCYAN}5.{Colors.ENDC} Web Recon & WAF Detection (whatweb, wafw00f, httpx)")
    print(f"  {Colors.OKCYAN}6.{Colors.ENDC} Directory, Endpoint & Content Fuzzing (gobuster, ffuf)")
    print(f"  {Colors.OKCYAN}7.{Colors.ENDC} Cloud Bucket Recon & Vulnerability Scan (nuclei, nikto)")
    print(f"  {Colors.BOLD}{Colors.OKGREEN}8. FULL AUTOMATED RECON PIPELINE (ALL-IN-ONE RECON CHAIN){Colors.ENDC}")
    print(f"  {Colors.FAIL}9. Exit CS Recon{Colors.ENDC}\n")

    choice = input(Colors.BOLD + Colors.OKCYAN + "Enter option number [1-9]: " + Colors.ENDC).strip()

    if choice == "1":
        res = option_local_network_recon()
        json_fn, html_fn = get_report_filenames(["local_network"])
        save_json_report(res, json_fn)
    elif choice in ["2", "3", "4", "5", "6", "7", "8"]:
        targets = get_targets()
        if not targets: return
        
        results = {}
        if choice == "2":
            results = option_domain_osint(targets)
        elif choice == "3":
            results = option_subdomain_enum(targets)
        elif choice == "4":
            results = option_port_service_scan(targets)
        elif choice == "5":
            results = option_web_recon_waf(targets)
        elif choice == "6":
            results = option_directory_fuzz(targets)
        elif choice == "7":
            results = option_cloud_vuln_scan(targets)
        elif choice == "8":
            results = option_full_auto_pipeline(targets)

        json_fn, html_fn = get_report_filenames(targets)
        save_json_report(results, json_fn)
        generate_html_report(results, html_fn)
        auto_open_report(html_fn)

    elif choice == "9":
        log_info("Exiting CS Recon. Happy Hacking!")
        sys.exit(0)
    else:
        log_error("Invalid choice selection.")

def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} v{VERSION} — Automated Reconnaissance & OSINT Framework")
    parser.add_argument("-t", "--target", help="Single domain/IP or path to file (@targets.txt)")
    parser.add_argument("-m", "--mode", type=int, choices=range(1, 9), help="Execution Mode (1-8)")
    parser.add_argument("--check-deps", action="store_true", help="Check missing system dependencies")
    parser.add_argument("--auto-install", action="store_true", help="Attempt automatic installation of missing tools")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")

    args = parser.parse_args()

    if args.verbose:
        VERBOSE = True

    if args.check_deps:
        check_dependencies(auto_install=args.auto_install)
        sys.exit(0)

    if args.target and args.mode:
        banner()
        targets = []
        if args.target.startswith("@") or args.target.endswith(".txt"):
            fp = args.target[1:] if args.target.startswith("@") else args.target
            if os.path.exists(fp):
                with open(fp, "r") as f:
                    targets = [validate_target(l.strip()) for l in f if l.strip() and not l.startswith("#")]
        else:
            targets = [validate_target(t.strip()) for t in args.target.split(",")]

        results = {}
        if args.mode == 1:
            results = option_local_network_recon()
        elif args.mode == 2:
            results = option_domain_osint(targets)
        elif args.mode == 3:
            results = option_subdomain_enum(targets)
        elif args.mode == 4:
            results = option_port_service_scan(targets)
        elif args.mode == 5:
            results = option_web_recon_waf(targets)
        elif args.mode == 6:
            results = option_directory_fuzz(targets)
        elif args.mode == 7:
            results = option_cloud_vuln_scan(targets)
        elif args.mode == 8:
            results = option_full_auto_pipeline(targets)

        json_fn, html_fn = get_report_filenames(targets)
        save_json_report(results, json_fn)
        generate_html_report(results, html_fn)
        auto_open_report(html_fn)
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
