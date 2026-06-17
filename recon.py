#!/usr/bin/env python3
"""
Recon Automation Tool v5.0 - Universal Web Security Scanner
Python port of recon.ps1
Features: JS Extract + CORS + CDN Bypass + Method Fuzz + Favicon + Cloud + WS + JWT
Output: HTML + JSON
"""

import sys
import argparse
import json
import re
import socket
import ssl
import hashlib
import base64
import time
import random
import concurrent.futures
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import requests
import dns.resolver
import dns.exception
from colorama import init, Fore, Style

init(autoreset=True)

VERSION = "5.0"


# =====================================================================
# WORDLISTS
# =====================================================================

WORDLIST = [
    "admin", "login", "api", "wp-admin", "wp-content", "backup", "config", ".env", "test",
    "dashboard", "uploads", "assets", "static", "js", "css", "images", "img", "vendor",
    "node_modules", "src", "app", "public", "private", "temp", "logs", "error", "404", "500",
    "robots.txt", "sitemap.xml", "cgi-bin", "includes", "modules", "plugins", "themes", "core",
    "data", "db", "database", "sql", "phpmyadmin", "administrator", "panel", "manager",
    "management", "console", "controlpanel", "cpanel", "webmail", "mail", "owa", "exchange",
    "autodiscover", "remote", "desktop", "rdp", "vpn", "proxy", "socks", "gateway", "portal",
    "intranet", "extranet", "help", "support", "chat", "contact", "about", "faq", "terms",
    "privacy", "license", "swagger", "docs", "api-docs", "api/v1", "api/v2", "graphql", "soap",
    "rest", "api/auth", "api/users", "api/admin", "api/config", "api/status", "api/health",
    "api/metrics", "api/logs", "api/debug", "api/.env", "api/swagger", "api/docs", "api/graphql",
    "user", "users", "member", "members", "customer", "customers", "client", "clients",
    "order", "orders", "cart", "checkout", "payment", "payments", "invoice", "invoices",
    "transaction", "transactions", "subscription", "subscriptions", "account", "accounts",
    "profile", "profiles", "setting", "settings", "preference", "preferences", "notification",
    "notifications", "message", "messages", "inbox", "outbox", "draft", "drafts", "search",
    "browse", "category", "categories", "product", "products", "item", "items", "service",
    "services", "page", "pages", "post", "posts", "article", "articles", "news", "blog",
    "gallery", "video", "videos", "media", "file", "files", "document", "documents",
    "download", "downloads", "upload", "uploads", "attachment", "attachments", "asset",
    "assets", "resource", "resources", "component", "components", "widget", "widgets",
    "template", "templates", "layout", "layouts", "theme", "themes", "style", "styles",
    "script", "scripts", "font", "fonts", "icon", "icons", "image", "images", "img",
    "picture", "pictures", "photo", "photos", "graphic", "graphics", "batch", "cron",
    "task", "tasks", "job", "jobs", "queue", "queues", "worker", "workers", "schedule",
    "schedules", "webhook", "webhooks", "callback", "callbacks", "hook", "hooks",
    "trigger", "triggers", "event", "events", "listen", "listener", "listeners",
    "broadcast", "broadcasts", "pub", "sub", "pubsub", "mqtt", "cache", "redis",
    "memcache", "memcached", "session", "sessions", "token", "tokens", "oauth", "oauth2",
    "openid", "saml", "sso", "ldap", "kerberos", "ntlm", "auth", "authenticate",
    "authorize", "login", "logout", "signin", "signup", "register", "registration",
    "verify", "verification", "reset", "password", "forgot", "recover", "recovery",
    "adminer", "adminer.php", "pgadmin", "phppgadmin", "mysql", "mariadb", "mongodb",
    "elasticsearch", "kibana", "grafana", "prometheus", "alertmanager", "consul", "vault",
    "nomad", "terraform", "ansible", "puppet", "chef", "docker", "kubernetes", "k8s",
    "rancher", "openshift", "istio", "envoy", "linkerd", "traefik", "nginx", "apache",
    "haproxy", "squid", "tinyproxy", "socks5", "socks4", "ssh", "ssh2", "telnet", "ftp",
    "sftp", "ftps", "smb", "smb2", "nfs", "nfs4", "webdav", "dav", "caldav", "carddav",
    "rss", "atom", "feed", "rdf", "xml", "json", "yaml", "yml", "toml", "ini", "cfg",
    "conf", "cnf", "reg", "registry", "install", "setup", "config", "configure",
    "configuration", ".htaccess", "htpasswd", "htgroup", "htdigest", "svn", ".svn",
    "git", ".git", "hg", ".hg", "bzr", ".bzr", "CVS", "cvs", ".cvs", "DS_Store",
    ".DS_Store", "_darcs", "P4CONFIG", "P4IGNORE", "crossdomain.xml",
    "clientaccesspolicy.xml", "security.txt", "humans.txt", "ads.txt", "app-ads.txt",
    "keybase.txt", "mta-sts.txt", "well-known", "/.well-known/security.txt", "actuator",
    "actuator/health", "actuator/info", "actuator/env", "actuator/beans",
    "actuator/mappings", "actuator/metrics", "actuator/configprops",
    "actuator/threaddump", "actuator/heapdump", "actuator/loggers", "actuator/logfile",
    "actuator/auditevents", "actuator/httptrace", "actuator/scheduledtasks",
    "swagger-ui.html", "swagger-ui/", "swagger-resources", "swagger.json", "swagger.yaml",
    "swagger.yml", "api/swagger.json", "api/swagger.yaml", "api/swagger.yml",
    "api/schema", "api/schemas", "openapi.json", "openapi.yaml", "openapi.yml",
    "api/openapi.json", "graphql", "graphiql", "playground", "api/graphql",
    "api/graphiql", "api/playground", "console", "admin/console",
    "administrator/console", "debug", "debug/", "debug/default/", "tests", "test/",
    "test/index.php", "test.php", "testing", "beta", "alpha", "staging", "stage",
    "dev", "development", "sandbox", "demo", "vercel", "netlify", "heroku", "aws",
    "azure", "gcp", "firebase", "cloud", "serverless", "lambda", "functions", "edge",
    "cdn", "fastly", "cloudfront", "cloudflare"
]

SUBDOMAIN_LIST = [
    "www", "mail", "remote", "blog", "shop", "api", "dev", "test", "admin", "cdn",
    "static", "assets", "images", "img", "video", "media", "download", "files", "ftp",
    "smtp", "pop3", "imap", "webmail", "owa", "exchange", "vpn", "proxy", "secure",
    "login", "portal", "app", "mobile", "m", "www2", "www3", "backup", "staging",
    "stage", "beta", "alpha", "demo", "sandbox", "dev2", "dev3", "test2", "monitor",
    "status", "help", "support", "docs", "wiki", "forum", "community", "chat", "board",
    "git", "svn", "jenkins", "jira", "confluence", "pma", "phpmyadmin", "sql", "db",
    "database", "config", "setup", "install", "license", "api", "gateway", "services",
    "service", "ns1", "ns2", "ns3", "ns4", "dns1", "dns2", "mx", "mx1", "mx2",
    "mail1", "mail2", "smtp", "pop3", "imap", "autodiscover", "autoconfig", "mta-sts",
    "caldav", "carddav", "webdav", "dav", "adminer", "pgadmin", "grafana", "kibana",
    "prometheus", "alertmanager", "consul", "vault", "nomad", "docker", "kubernetes",
    "k8s", "rancher", "rancher2", "istio", "traefik", "haproxy", "nginx", "jenkins",
    "jira", "confluence", "bitbucket", "sonar", "sonarqube", "nexus", "artifactory",
    "gitlab", "gitea", "gogs", "github", "gitlab-ci", "jenkins-ci", "teamcity",
    "bamboo", "buddy", "argocd", "argo", "spinnaker", "drone", "circleci", "travis-ci",
    "redis", "memcache", "memcached", "mongo", "mongodb", "mysql", "pgsql", "postgres",
    "couchdb", "cassandra", "elasticsearch", "elastic", "kibana", "logstash", "rabbitmq",
    "activemq", "kafka", "zookeeper", "etcd", "consul", "report", "reports", "analytics",
    "stats", "statistics", "logs", "log", "logging", "docs", "doc", "documentation",
    "api-docs", "apidocs", "swagger", "swagger-ui", "graphql", "graphiql", "playground",
    "hasura", "prisma", "status", "uptime", "health", "monitor", "monitoring", "ping",
    "heartbeat", "cdn2", "cdn3", "static2", "media2", "img2", "assets2", "mail2",
    "smtp2", "pop2", "imap2", "vpn2", "proxy2", "secure2", "remote2", "dev1", "dev3",
    "dev4", "dev5", "test1", "test3", "test4", "test5", "staging2", "staging3", "prod",
    "production", "preprod", "pre-prod", "dr", "disaster-recovery", "backup2", "backup3",
    "internal", "external", "corp", "corporate", "partner", "partners", "vendor",
    "vendors", "supplier", "suppliers", "distributor", "distributors", "reseller",
    "resellers", "affiliate", "affiliates", "wholesale", "retail", "store", "shop2",
    "career", "careers", "job", "jobs", "recruit", "recruitment", "hr",
    "human-resources", "payroll", "benefits", "legal", "compliance", "audit", "auditor",
    "finance", "accounting", "tax", "taxes", "billing", "invoice", "invoices", "ticket",
    "tickets", "support2", "helpdesk", "forum2", "community2", "user", "users",
    "profile", "profiles", "member", "members", "account", "accounts", "my", "myaccount",
    "dashboard2", "panel2", "manager2", "crm", "erp", "hris", "lms", "scorm",
    "analytics2", "stats2", "metrics", "bug", "bugs", "issue", "issues", "feedback",
    "suggestion", "suggestions", "roadmap", "changelog", "release", "releases", "blog2",
    "news", "newsletter", "event", "events", "webinar", "webinars", "training", "learn",
    "academy", "education", "statuspage", "status-page", "uptime2"
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521,
    2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 9090, 10000, 11211, 27017
]

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9000: "PHP-FPM", 9090: "JavaConsole",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB"
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "curl/8.4.0"
]

# =====================================================================
# HELPERS
# =====================================================================

session = requests.Session()
session.verify = False
requests.packages.urllib3.disable_warnings()


def log(msg, color=Fore.WHITE):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{color}[{timestamp}] {msg}{Style.RESET_ALL}")


def debug_msg(msg, verbose):
    if verbose:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.LIGHTBLACK_EX}[{timestamp}] [DEBUG] {msg}{Style.RESET_ALL}")


def section(name):
    print(f"\n{Fore.YELLOW}====== {name} ======{Style.RESET_ALL}")


def clean_target(t):
    t = t.strip().lower()
    t = re.sub(r'^https?://', '', t)
    t = re.sub(r'/.*$', '', t)
    return t


def to_url(t):
    t = t.strip().lower()
    if not t.startswith(('http://', 'https://')):
        t = f"https://{t}"
    return t


def get_random_ua():
    return random.choice(USER_AGENTS)


def request_safe(url, method="GET", timeout=15, body=None, content_type=None, headers=None, max_retries=3, verbose=False):
    for attempt in range(max_retries):
        try:
            req_headers = {"User-Agent": get_random_ua()}
            if headers:
                req_headers.update(headers)
            if body and content_type:
                req_headers["Content-Type"] = content_type

            resp = session.request(
                method, url, headers=req_headers, data=body,
                timeout=timeout, allow_redirects=True
            )

            if resp.status_code == 429:
                wait = 30
                if "Retry-After" in resp.headers:
                    try:
                        wait = int(resp.headers["Retry-After"])
                    except ValueError:
                        pass
                wait = min(wait, 60)
                debug_msg(f"429 rate limited, waiting {wait}s (attempt {attempt+1}/{max_retries})", verbose)
                if attempt < max_retries - 1:
                    time.sleep(wait)
                    continue
            return resp
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                wait = pow(2, attempt + 1)
                debug_msg(f"Request failed ({e}), retry {attempt+1}/{max_retries} in {wait}s", verbose)
                time.sleep(wait)
            else:
                return None
    return None


def request_method(url, method, timeout=8):
    try:
        req_headers = {"User-Agent": get_random_ua()}
        resp = session.request(method, url, headers=req_headers, timeout=timeout, allow_redirects=True)
        return {"status": resp.status_code, "len": len(resp.text)}
    except requests.exceptions.RequestException:
        return None


def run_parallel(items, func, max_workers=20, label="", verbose=False):
    results = []
    if not items:
        return results
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(func, item): item for item in items}
        for i, future in enumerate(concurrent.futures.as_completed(future_map)):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception:
                pass
    return results


def test_port(host, port, timeout_ms=2000):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_ms / 1000.0)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


# =====================================================================
# 1. IP RESOLUTION
# =====================================================================

def scan_ip(base_url, target_clean, results, verbose=False):
    section("IP RESOLUTION")
    try:
        ips = list(set(
            addr[4][0] for addr in socket.getaddrinfo(target_clean, 80)
        ))
        results["ip"] = ips
        for ip in ips:
            log(f"  [IP] {target_clean} -> {ip}", Fore.GREEN)
    except Exception:
        log(f"  Could not resolve {target_clean}", Fore.RED)


# =====================================================================
# 2. SECURITY HEADERS + WAF DETECTION
# =====================================================================

def scan_security_headers(base_url, target_clean, results, verbose=False):
    section("SECURITY HEADERS + WAF DETECTION")

    resp = request_safe(base_url, timeout=15, verbose=verbose)
    if resp is None:
        log(f"Failed to fetch {base_url}", Fore.RED)
        return

    results["http_status"] = resp.status_code
    results["page_size"] = len(resp.text)

    headers_to_check = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-Frame-Options": "X-Frame-Options",
        "X-XSS-Protection": "X-XSS-Protection",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
        "Access-Control-Allow-Origin": "CORS",
        "Set-Cookie": "Secure/HttpOnly Cookies",
    }

    present = []
    missing = []
    for h, label in headers_to_check.items():
        if h.lower() in [k.lower() for k in resp.headers]:
            present.append(label)
            log(f"  [OK] {label}", Fore.GREEN)
        else:
            missing.append(label)
            log(f"  [WARN] {label} missing", Fore.YELLOW)

    results["headers_present"] = present
    results["headers_missing"] = missing

    waf = []
    waf_headers = {
        "CF-Cache-Status": "Cloudflare",
        "CF-Ray": "Cloudflare",
        "X-Sucuri-ID": "Sucuri",
        "X-Sucuri-Cache": "Sucuri",
        "X-Edge-Location": "StackPath",
        "X-WAF-Event-Info": "StackPath",
        "X-Akamai-Transformed": "Akamai",
        "X-Akamai-Request-ID": "Akamai",
        "X-Nginx-Proxy": "Nginx WAF",
        "X-Mod-Security": "ModSecurity",
        "X-Protected-By": "SiteGround",
        "X-Iinfo": "Incapsula/Imperva",
        "X-CDN": "CDN (generic)",
    }

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for h, label in waf_headers.items():
        if h.lower() in headers_lower:
            waf.append(label)

    if "server" in headers_lower:
        srv = headers_lower["server"]
        if "cloudflare" in srv.lower():
            waf.append("Cloudflare")
        if "akamai" in srv.lower():
            waf.append("Akamai")
        if "sucuri" in srv.lower():
            waf.append("Sucuri")
        if "aws" in srv.lower():
            waf.append("AWS")

    if "set-cookie" in headers_lower:
        ck = headers_lower["set-cookie"]
        if "__cfduid" in ck:
            waf.append("Cloudflare")
        if "ak_bmsc" in ck:
            waf.append("Akamai Blockchain")
        if "visid_incap" in ck:
            waf.append("Incapsula")
        if "nlbi_" in ck:
            waf.append("Incapsula")

    results["waf"] = list(set(w.lower() for w in waf))
    if results["waf"]:
        for w in results["waf"]:
            log(f"  [WAF] {w} detected", Fore.YELLOW)
    else:
        log("  [WAF] No WAF detected", Fore.GREEN)

    tech = []
    if "server" in headers_lower:
        tech.append(f"Server:{resp.headers.get('Server', '')}")
    if "x-powered-by" in headers_lower:
        tech.append(resp.headers.get("X-Powered-By", ""))
    if "x-generator" in headers_lower:
        tech.append(resp.headers.get("X-Generator", ""))
    results["tech"] = tech

    score = round(len(present) / len(headers_to_check) * 100) if headers_to_check else 0
    results["score"] = score
    log(f"Security Score: {score}/100", Fore.GREEN)

    return resp


# =====================================================================
# 3. DIRECTORY SCAN
# =====================================================================

def scan_directories(base_url, target_clean, results, depth=1, custom_wordlist=None, verbose=False):
    wordlist = custom_wordlist if custom_wordlist else WORDLIST
    section(f"DIRECTORY SCAN ({len(wordlist)} paths, depth={depth})")

    found = []
    scanned = set()

    def check_path(item):
        url = item["base"] + "/" + item["path"]
        try:
            req_headers = {"User-Agent": get_random_ua()}
            resp = session.get(url, headers=req_headers, timeout=8, allow_redirects=True)
            if resp.status_code not in (404, 429):
                return {"path": url, "code": resp.status_code, "level": item["level"]}
        except requests.exceptions.RequestException:
            pass
        return None

    def scan_level(url_base, level, paths):
        items = [{"path": p, "base": url_base, "level": level} for p in paths]
        return run_parallel(items, check_path, max_workers=20, label=f"Dir Scan L{level}", verbose=verbose)

    found1 = scan_level(base_url, 1, wordlist)
    found.extend(found1)
    for d in found1:
        color = Fore.GREEN if d["code"] <= 400 else Fore.YELLOW
        log(f"  [FOUND] {d['path']} ({d['code']})", color)
        scanned.add(d["path"].lower())

    if depth >= 2:
        subdirs = [d for d in found1 if d["code"] in (200, 301, 302, 403)]
        for lvl in range(2, depth + 1):
            next_paths = []
            for sd in subdirs:
                dir_url = sd["path"].rstrip("/")
                sub_results = scan_level(dir_url, lvl, wordlist)
                for sr in sub_results:
                    if sr["path"].lower() not in scanned:
                        color = Fore.GREEN if sr["code"] <= 400 else Fore.YELLOW
                        log(f"  [FOUND] {sr['path']} ({sr['code']})", color)
                        found.append(sr)
                        scanned.add(sr["path"].lower())
                        if sr["code"] in (200, 301, 302, 403):
                            next_paths.append(sr)
            subdirs = next_paths

    results["dirs"] = found
    log(f"Found {len(found)} accessible paths (depth={depth})", Fore.CYAN)


# =====================================================================
# 4. SUBDOMAIN ENUMERATION
# =====================================================================

def scan_subdomains(base_url, target_clean, results, verbose=False):
    section(f"SUBDOMAIN ENUMERATION ({len(SUBDOMAIN_LIST)} subs)")

    def check_sub(item):
        url = f"https://{item['sub']}.{item['target']}"
        try:
            req_headers = {"User-Agent": get_random_ua()}
            resp = session.get(url, headers=req_headers, timeout=8, allow_redirects=True)
            if resp.status_code not in (404, 429):
                return {"subdomain": item["sub"], "url": url, "status": resp.status_code}
        except requests.exceptions.RequestException:
            try:
                socket.getaddrinfo(f"{item['sub']}.{item['target']}", 80)
                return {"subdomain": item["sub"], "url": url, "status": "DNS-only"}
            except Exception:
                pass
        return None

    items = [{"sub": s, "target": target_clean} for s in SUBDOMAIN_LIST]
    found = run_parallel(items, check_sub, max_workers=30, label="Subdomain Scan", verbose=verbose)
    found = [f for f in found if f]

    results["subdomains"] = found
    for f in found:
        log(f"  [FOUND] {f['url']} ({f['status']})", Fore.GREEN)
    log(f"Found {len(found)} subdomains", Fore.CYAN)


# =====================================================================
# 5. PORT SCAN
# =====================================================================

def scan_ports(base_url, target_clean, results, verbose=False):
    section(f"PORT SCAN ({len(COMMON_PORTS)} ports)")

    def check_port(item):
        if test_port(item["host"], item["port"], 2000):
            return item["port"]
        return None

    items = [{"host": target_clean, "port": p} for p in COMMON_PORTS]
    open_ports = run_parallel(items, check_port, max_workers=35, label="Port Scan", verbose=verbose)
    open_ports = sorted([p for p in open_ports if p])

    results["ports"] = open_ports
    for p in open_ports:
        svc = PORT_SERVICE_MAP.get(p, "Unknown")
        log(f"  [OPEN] Port {p} ({svc})", Fore.RED)
    log(f"Found {len(open_ports)} open ports", Fore.CYAN)


# =====================================================================
# 6. DNS ENUMERATION
# =====================================================================

def scan_dns(base_url, target_clean, results, verbose=False):
    section("DNS ENUMERATION")
    dns_records = {}

    try:
        answers = socket.getaddrinfo(target_clean, 80)
        a_records = list(set(a[4][0] for a in answers))
        if a_records:
            dns_records["A"] = a_records
            log(f"  [A] {', '.join(a_records)}", Fore.GREEN)
    except Exception:
        pass

    record_types = ["MX", "NS", "TXT", "CNAME"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target_clean, rtype, lifetime=5)
            vals = [str(r) for r in answers]
            if vals:
                dns_records[rtype] = vals
                for v in vals:
                    log(f"  [{rtype}] {v}", Fore.GREEN)
        except (dns.exception.Timeout, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass

    try:
        answers = dns.resolver.resolve(target_clean, "SOA", lifetime=5)
        soa_vals = [str(r) for r in answers]
        if soa_vals:
            dns_records["SOA"] = soa_vals
            log(f"  [SOA] {soa_vals[0]}", Fore.GREEN)
    except Exception:
        pass

    results["dns"] = dns_records
    log(f"DNS records found: {len(dns_records)}", Fore.CYAN)


# =====================================================================
# 7. SSL/TLS ANALYSIS
# =====================================================================

def scan_ssl(base_url, target_clean, results, verbose=False):
    section("SSL/TLS ANALYSIS")

    if not base_url.startswith("https"):
        log("  Skipped (HTTP only)", Fore.YELLOW)
        return

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((target_clean, 443), timeout=10)
        ssock = context.wrap_socket(sock, server_hostname=target_clean)
        cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject_str = str(cert.get("subject", []))
        issuer_str = str(cert.get("issuer", []))
        valid_from = cert.get("notBefore", "N/A")
        valid_to = cert.get("notAfter", "N/A")

        log(f"  Subject: {subject_str}", Fore.GREEN)
        log(f"  Issuer: {issuer_str}", Fore.GREEN)
        log(f"  Valid: {valid_from} -> {valid_to}", Fore.GREEN)

        results["ssl"] = {
            "subject": subject_str,
            "issuer": issuer_str,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "algorithm": str(ssock.cipher()[0]) if ssock.cipher() else "N/A",
            "key_size": ssock.cipher()[2] if ssock.cipher() else 0,
        }

        try:
            valid_to_clean = valid_to.replace(" GMT", "").strip()
            exp_date = None
            for fmt in ["%b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"]:
                try:
                    exp_date = datetime.strptime(valid_to_clean, fmt)
                    break
                except ValueError:
                    continue
            if exp_date:
                days_left = (exp_date - datetime.now()).days
                if days_left < 30:
                    log(f"  [WARN] Certificate expires in {days_left} days!", Fore.RED)
                else:
                    log(f"  Certificate expires in {days_left} days", Fore.GREEN)
                results["ssl_days_left"] = days_left
        except Exception:
            pass

        ssock.close()
        sock.close()
    except Exception as e:
        log(f"  SSL analysis failed: {e}", Fore.RED)


# =====================================================================
# 8. TECH FINGERPRINTING
# =====================================================================

def scan_tech_fingerprint(base_url, target_clean, results, verbose=False):
    section("TECH FINGERPRINTING")
    techs = []

    resp = request_safe(base_url, timeout=10, verbose=verbose)
    if resp is None:
        log("  No response", Fore.RED)
        return

    content = resp.text

    if re.search(r'react(\.development|\.production)?\.js|__NEXT_DATA__|next\.js|next/static', content, re.I):
        techs.append("Next.js")
    if re.search(r'vue(\.min)?\.js|__VUE__|createApp|vue-router', content, re.I):
        techs.append("Vue.js")
    if re.search(r'angular\.(min\.)?js|ng-app|ng-version|angular\.core', content, re.I):
        techs.append("Angular")
    if re.search(r'jquery(\.min)?\.js|\$\(function|jQuery', content, re.I):
        techs.append("jQuery")
    if re.search(r'svelte|__SVELTE__', content, re.I):
        techs.append("Svelte")
    if re.search(r'alpine\.(min\.)?js|x-data', content, re.I):
        techs.append("Alpine.js")
    if re.search(r'htmx(\.min)?\.js|hx-get|hx-post', content, re.I):
        techs.append("HTMX")
    if re.search(r'livewire|wire:', content, re.I):
        techs.append("Livewire")
    if re.search(r'turbo\.(min\.)?js|Turbo\.visit', content, re.I):
        techs.append("Turbo/Hotwire")
    if re.search(r'tailwindcss|\.tw-|text-\[#|bg-\[#', content, re.I):
        techs.append("Tailwind CSS")
    if re.search(r'bootstrap(\.min)?\.css|col-(xs|sm|md|lg)-|glyphicon', content, re.I):
        techs.append("Bootstrap")
    if re.search(r'csrf-token|laravel|livewire', content, re.I):
        techs.append("Laravel")
    if re.search(r'wp-content|wp-includes|wp-json', content, re.I):
        techs.append("WordPress")
    if re.search(r'drupal|Drupal\.|drupalSettings', content, re.I):
        techs.append("Drupal")
    if re.search(r'Joomla|joomla|\.joomla', content, re.I):
        techs.append("Joomla")
    if re.search(r'__INITIAL_STATE__|__NEXT_DATA__|_app\.jsx', content, re.I):
        techs.append("React/Next.js")
    if resp.headers.get("X-Powered-By"):
        techs.append(f"Powered-By:{resp.headers['X-Powered-By']}")
    if resp.headers.get("Server"):
        techs.append(f"Server:{resp.headers['Server']}")

    results["tech_fp"] = list(set(techs))
    for t in results["tech_fp"]:
        log(f"  [TECH] {t}", Fore.GREEN)
    if not results["tech_fp"]:
        log("  No technologies detected", Fore.YELLOW)


# =====================================================================
# 9. CMS DETECTION
# =====================================================================

def scan_cms(base_url, target_clean, results, verbose=False):
    section("CMS DETECTION")
    cms = []

    wp_checks = ["/wp-content/", "/wp-admin/", "/wp-includes/", "/wp-json/", "/xmlrpc.php", "/wp-login.php"]
    wp_match = 0
    for p in wp_checks:
        r = request_safe(base_url + p, timeout=5, verbose=verbose)
        if r and r.status_code != 404:
            wp_match += 1
    if wp_match >= 2:
        cms.append("WordPress")
        log("  [CMS] WordPress", Fore.GREEN)

    j_checks = ["/components/", "/modules/", "/templates/", "/administrator/", "/media/", "/includes/"]
    j_match = 0
    for p in j_checks:
        r = request_safe(base_url + p, timeout=5, verbose=verbose)
        if r and r.status_code != 404:
            j_match += 1
    if j_match >= 2:
        cms.append("Joomla")
        log("  [CMS] Joomla", Fore.GREEN)

    d_checks = ["/sites/", "/core/", "/modules/", "/themes/", "/node/", "/user/"]
    d_match = 0
    for p in d_checks:
        r = request_safe(base_url + p, timeout=5, verbose=verbose)
        if r and r.status_code != 404:
            d_match += 1
    if d_match >= 2:
        cms.append("Drupal")
        log("  [CMS] Drupal", Fore.GREEN)

    try:
        r = request_safe(base_url, timeout=5, verbose=verbose)
        if r and re.search(r'laravel|csrf-token|livewire|Laravel', r.text, re.I):
            cms.append("Laravel")
            log("  [CMS] Laravel", Fore.GREEN)
    except Exception:
        pass

    m_checks = ["/static/version", "/pub/", "/media/", "/skin/", "/index.php/admin"]
    m_match = 0
    for p in m_checks:
        r = request_safe(base_url + p, timeout=5, verbose=verbose)
        if r and r.status_code != 404:
            m_match += 1
    if m_match >= 2:
        cms.append("Magento/Adobe Commerce")
        log("  [CMS] Magento", Fore.GREEN)

    results["cms"] = cms
    if not cms:
        log("  No CMS detected", Fore.YELLOW)


# =====================================================================
# 10. VULNERABILITY CHECKS
# =====================================================================

def scan_vulns(base_url, target_clean, results, verbose=False):
    section("VULNERABILITY CHECKS")
    vulns = []

    vuln_paths = [
        "/.env", "/wp-config.php.bak", "/config.php.bak", "/config.bak", "/db.sql",
        "/dump.sql", "/backup.sql", "/.git/config", "/.svn/entries", "/crossdomain.xml",
        "/clientaccesspolicy.xml", "/phpinfo.php", "/info.php", "/debug", "/api/debug",
        "/actuator", "/actuator/health", "/swagger-ui.html", "/api/swagger",
        "/graphql?query={__schema{types{name}}}", "/server-status", "/server-info",
        "/phpmyadmin/", "/.aws/credentials", "/credentials", "/secrets", "/secret",
        "/keys", "/tokens", "/robots.txt", "/sitemap.xml", "/security.txt", "/Dockerfile",
        "/docker-compose.yml", "/.docker/config.json", "/npm-debug.log", "/yarn-debug.log",
        "/composer.json", "/package.json", "/web.config", "/nginx.conf", "/.htaccess",
        "/htaccess", "/.npmrc", "/.env.local", "/api/.env", "/admin/.env", "/config/.env",
        "/actuator/env", "/actuator/beans", "/actuator/heapdump", "/actuator/threaddump",
        "/swagger-resources", "/v2/api-docs", "/v3/api-docs", "/openapi.json",
        "/_debug/", "/dev/", "/test/", "/tests/", "/staging/", "/beta/"
    ]

    def check_vuln(item):
        url = item["base"] + item["path"]
        try:
            req_headers = {"User-Agent": get_random_ua()}
            resp = session.get(url, headers=req_headers, timeout=5, allow_redirects=True)
            if resp.status_code not in (404, 429, 403):
                return {"path": item["path"], "code": resp.status_code}
        except requests.exceptions.RequestException:
            pass
        return None

    items_vuln = [{"path": p, "base": base_url} for p in vuln_paths]
    vuln_results = run_parallel(items_vuln, check_vuln, max_workers=20, label="Vuln Path Scan", verbose=verbose)

    for vr in vuln_results:
        if vr:
            vulns.append(f"{vr['path']} (HTTP {vr['code']})")
            log(f"  [VULN] {vr['path']} -> HTTP {vr['code']}", Fore.RED)

    http_url = base_url.replace("https://", "http://")
    if http_url != base_url:
        try:
            r = request_safe(http_url, timeout=5, verbose=verbose)
            if r and r.status_code < 400:
                vulns.append("HTTP available (no forced HTTPS redirect)")
                log("  [VULN] HTTP available (no forced redirect)", Fore.RED)
        except Exception:
            pass

    act_checks = ["/actuator", "/actuator/env", "/actuator/heapdump"]
    for p in act_checks:
        try:
            r = request_safe(base_url + p, timeout=5, verbose=verbose)
            if r and r.status_code == 200 and re.search(r'spring|springframework', r.text, re.I):
                vulns.append("Spring Boot Actuator exposed (CVE-2023-xxxx) - sensitive endpoints")
                log("  [VULN] Spring Boot actuator exposed! (CVE potential)", Fore.RED)
                break
        except Exception:
            pass

    try:
        r = request_safe(base_url + "/.git/HEAD", timeout=5, verbose=verbose)
        if r and r.status_code == 200 and 'ref:' in r.text:
            vulns.append("Git repository exposed (.git/HEAD)")
            log("  [VULN] .git repository exposed!", Fore.RED)
    except Exception:
        pass

    sqli_payloads = ["'", "\"", "1' OR 1=1", "1\" OR \"1\"=\"1", "' OR 1=1--", "admin'--"]
    for payload in sqli_payloads:
        try:
            url = f"{base_url}/api?q={quote(payload)}"
            r = request_safe(url, timeout=5, verbose=verbose)
            if r and re.search(r'sql|syntax|mysql|oracle|postgres|odbc|db2|sqlite|driver|unclosed|quoted', r.text, re.I):
                vulns.append("Potential SQLi in /api?q= (error-based)")
                log("  [VULN] Potential SQLi detected!", Fore.RED)
                break
        except Exception:
            pass

    try:
        url = f"{base_url}?q=%3Cscript%3Ealert(1)%3C/script%3E"
        r = request_safe(url, timeout=5, verbose=verbose)
        if r and '<script>alert(1)</script>' in r.text:
            vulns.append("Potential XSS (reflected)")
            log("  [VULN] Potential XSS detected!", Fore.RED)
    except Exception:
        pass

    lfi_paths = [
        "/index.php?page=../../../etc/passwd", "/page=../../../etc/passwd",
        "/api?file=../../../etc/passwd", "/download?file=../../../etc/passwd"
    ]
    for p in lfi_paths:
        try:
            r = request_safe(base_url + p, timeout=5, verbose=verbose)
            if r and re.search(r'root:|bin:/', r.text):
                vulns.append(f"Potential LFI: {p}")
                log("  [VULN] Potential LFI detected!", Fore.RED)
                break
        except Exception:
            pass

    results["vulns"] = list(set(vulns))
    color = Fore.RED if results["vulns"] else Fore.GREEN
    log(f"Found {len(results['vulns'])} potential vulnerabilities", color)


# =====================================================================
# 11. WAYBACK MACHINE
# =====================================================================

def scan_wayback(base_url, target_clean, results, verbose=False):
    section("WAYBACK MACHINE (archive.org)")
    wayback = []

    url = f"http://web.archive.org/cdx/search/cdx?url=*.{target_clean}/*&output=json&limit=100&fl=original,timestamp,statuscode"
    try:
        r = request_safe(url, timeout=15, verbose=verbose)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if len(data) > 1:
                    for i in range(1, min(len(data), 20)):
                        entry = data[i]
                        if len(entry) >= 3:
                            wayback.append({"url": entry[0], "date": entry[1], "status": entry[2]})
                            log(f"  [WAYBACK] {entry[1]} {entry[2]} {entry[0]}", Fore.GREEN)
                    log(f"Total archived snapshots: {len(data) - 1}", Fore.CYAN)
                else:
                    log("  No archived URLs found", Fore.YELLOW)
            except (json.JSONDecodeError, IndexError):
                log("  Could not parse Wayback response", Fore.YELLOW)
        else:
            log("  Wayback machine check failed", Fore.YELLOW)
    except Exception as e:
        log(f"  Wayback machine check failed: {e}", Fore.YELLOW)

    results["wayback"] = wayback


# =====================================================================
# 12. API FUZZING
# =====================================================================

def scan_api_fuzz(base_url, target_clean, results, verbose=False):
    section("API FUZZING")
    api_finds = []

    gql_url = f"{base_url}/graphql"
    gql_body = '{"query":"{__schema{types{name fields{name}}}}"}'
    try:
        r = request_safe(gql_url, method="POST", body=gql_body, content_type="application/json", timeout=8, verbose=verbose)
        if r and '__schema' in r.text:
            api_finds.append("GraphQL endpoint allows introspection!")
            log("  [API] GraphQL introspection enabled!", Fore.RED)
    except Exception:
        pass

    gql_paths = ["/graphql", "/graphiql", "/api/graphql", "/query", "/api/query", "/v1/graphql", "/v2/graphql"]
    for p in gql_paths:
        try:
            r = request_safe(base_url + p, method="POST", body='{"query":"{__typename}"}',
                             content_type="application/json", timeout=5, verbose=verbose)
            if r and ('__typename' in r.text or r.status_code == 200):
                api_finds.append(f"GraphQL endpoint at {p}")
                log(f"  [API] GraphQL endpoint: {p}", Fore.YELLOW)
                break
        except Exception:
            pass

    api_docs = ["/api/docs", "/api/swagger", "/swagger-ui.html", "/api/v1/docs", "/api/v2/docs", "/docs/api"]
    for p in api_docs:
        try:
            r = request_safe(base_url + p, timeout=5, verbose=verbose)
            if r and r.status_code == 200:
                api_finds.append(f"API docs at {p}")
                log(f"  [API] API documentation: {p}", Fore.YELLOW)
        except Exception:
            pass

    endpoints = ["/api/users", "/api/admin", "/api/config", "/api/settings", "/api/status"]
    for ep in endpoints:
        try:
            r = request_safe(base_url + ep, timeout=5, verbose=verbose)
            if r and r.status_code == 200 and re.search(r'\[|\{|"', r.text):
                api_finds.append(f"{ep} returns data (no auth required?)")
                log(f"  [API] {ep} accessible without auth", Fore.RED)
        except Exception:
            pass

    results["api_fuzz"] = list(set(api_finds))
    if not results["api_fuzz"]:
        log("  No API issues found", Fore.GREEN)


# =====================================================================
# 13. EMAIL EXTRACTION
# =====================================================================

def scan_emails(base_url, target_clean, results, verbose=False):
    section("EMAIL EXTRACTION")
    emails = []
    email_regex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    pages_to_check = [base_url, f"{base_url}/contact", f"{base_url}/about", f"{base_url}/team",
                      f"{base_url}/people", f"{base_url}/staff", f"{base_url}/directory"]

    for page in pages_to_check:
        resp = request_safe(page, timeout=10, verbose=verbose)
        if resp and resp.text:
            found = set(email_regex.findall(resp.text))
            for e in found:
                e_lower = e.lower()
                if not re.search(r'\.png|\.jpg|\.css|example\.com|\.local|\.test|@example', e_lower, re.I):
                    if e_lower not in emails:
                        log(f"  [EMAIL] {e_lower}", Fore.GREEN)
                        emails.append(e_lower)

    results["emails"] = emails
    log(f"Found {len(emails)} email addresses", Fore.CYAN)


# =====================================================================
# 14. JS ENDPOINT EXTRACTION
# =====================================================================

def scan_js_extract(base_url, target_clean, results, verbose=False):
    section("JS ENDPOINT EXTRACTION")

    resp = request_safe(base_url, timeout=10, verbose=verbose)
    if resp is None or not resp.text:
        log("  No response", Fore.RED)
        return

    content = resp.text
    js_endpoints = []
    api_keys = []
    js_files = []

    js_patterns = [
        r'src=["\']([^"\']+\.js[^"\']*)["\']',
        r'href=["\']([^"\']+\.js[^"\']*)["\']',
        r'import\s+["\']([^"\']+\.js)["\']',
    ]
    for pat in js_patterns:
        for m in re.finditer(pat, content, re.I):
            js_url = m.group(1)
            if js_url.startswith("//"):
                js_url = "https:" + js_url
            elif js_url.startswith("/"):
                js_url = base_url.rstrip("/") + js_url
            elif not re.match(r'^https?://', js_url):
                js_url = base_url.rstrip("/") + "/" + js_url
            js_files.append(js_url)

    js_files = list(set(js_files))

    endpoint_regex = re.compile(r'(?:["\'])(/[a-zA-Z0-9/_.-]+)(?:["\']|\\n)')
    ep_matches = endpoint_regex.findall(content)
    for ep in ep_matches:
        if re.search(r'\.(css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$', ep, re.I):
            continue
        if ep not in js_endpoints:
            js_endpoints.append(ep)

    js_limit = 5
    js_parsed = 0
    for js_file in js_files:
        if js_parsed >= js_limit:
            break
        debug_msg(f"Parsing JS: {js_file}", verbose)
        js_resp = request_safe(js_file, timeout=8, verbose=verbose)
        if js_resp is None or not js_resp.text:
            continue
        js_parsed += 1
        js_content = js_resp.text

        jep = endpoint_regex.findall(js_content)
        for ep in jep:
            if re.search(r'\.(css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$', ep, re.I):
                continue
            if ep not in js_endpoints:
                js_endpoints.append(ep)

        api_pats = [
            r'api["\']?\s*[:=]\s*["\']?([^"\';\s]+)["\']?',
            r'endpoint["\']?\s*[:=]\s*["\']?([^"\';\s]+)["\']?',
            r'baseURL["\']?\s*[:=]\s*["\']?([^"\';\s]+)["\']?',
        ]
        for apat in api_pats:
            for m in re.finditer(apat, js_content, re.I):
                v = m.group(1)
                if "://" not in v:
                    v = base_url.rstrip("/") + v
                if v not in js_endpoints:
                    js_endpoints.append(v)

        key_pats = [
            r'(?:api[_-]?key|apikey|secret|token|bearer|auth)[:"\'\s]*["\']([a-zA-Z0-9_\-]{16,})["\']',
            r'(AIza[0-9A-Za-z\-_]{35})',
            r'(sk-[a-zA-Z0-9]{32,})',
            r'(ghp_[a-zA-Z0-9]{36})',
            r'(AKIA[0-9A-Z]{16})',
        ]
        for kpat in key_pats:
            for m in re.finditer(kpat, js_content, re.I):
                v = m.group(1) if m.lastindex else m.group(0)
                if v not in api_keys:
                    api_keys.append(v)
                    log(f"  [KEY] {v}", Fore.RED)

    results["js_endpoints"] = list(set(js_endpoints))
    results["api_keys"] = api_keys
    results["js_files"] = js_files

    for ep in results["js_endpoints"]:
        log(f"  [ENDPOINT] {ep}", Fore.GREEN)
    if api_keys:
        log(f"  [WARN] {len(api_keys)} API keys/secrets found!", Fore.RED)
    log(f"Found {len(results['js_endpoints'])} endpoints in JS, {len(api_keys)} keys", Fore.CYAN)


# =====================================================================
# 15. CORS MISCONFIGURATION
# =====================================================================

def scan_cors(base_url, target_clean, results, verbose=False):
    section("CORS MISCONFIGURATION")
    cors_issues = []

    evil_origins = ["https://evil.com", "https://null.evil.com", "null", f"https://{target_clean}.evil.com"]

    for origin in evil_origins:
        try:
            req_headers = {"User-Agent": get_random_ua(), "Origin": origin}
            r = session.options(base_url, headers=req_headers, timeout=8, allow_redirects=True)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if acao and (acao == "*" or origin in acao):
                cors_issues.append(f"CORS allows Origin: {origin} -> ACAO: {acao}")
                log(f"  [CORS] Allows {origin} (ACAO: {acao})", Fore.RED)
        except Exception:
            pass

    try:
        req_headers = {"User-Agent": get_random_ua(), "Origin": "https://evil.com"}
        r = session.get(base_url, headers=req_headers, timeout=8, allow_redirects=True)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao in ("*", "https://evil.com"):
            cors_issues.append(f"CORS reflects Origin header: {acao}")
            log(f"  [CORS] Reflects origin: {acao}", Fore.RED)
    except Exception:
        pass

    results["cors"] = list(set(cors_issues))
    if not results["cors"]:
        log("  No CORS issues found", Fore.GREEN)


# =====================================================================
# 16. CDN ORIGIN IP BYPASS
# =====================================================================

def scan_cdn_bypass(base_url, target_clean, results, verbose=False):
    section("CDN ORIGIN IP BYPASS")
    origin_ips = []

    try:
        ips = list(set(
            addr[4][0] for addr in socket.getaddrinfo(target_clean, 80)
        ))
        for ip in ips:
            if ip.startswith(("104.", "172.", "103.")):
                continue
            try:
                req_headers = {"User-Agent": get_random_ua(), "Host": target_clean}
                url = f"https://{ip}/"
                r = session.get(url, headers=req_headers, timeout=8, allow_redirects=True)
                if r.status_code in (200, 301, 302):
                    origin_ips.append(f"{ip} -> {target_clean} (HTTP {r.status_code})")
                    log(f"  [ORIGIN] {ip} -> {target_clean}", Fore.RED)
            except Exception:
                pass
    except Exception:
        pass

    origin_subs = ["origin", "origin-www", "direct", "direct-www", "lb", "server", "web", "web1", "web2", "backend", "internal"]
    for sub in origin_subs:
        try:
            sub_ips = list(set(
                addr[4][0] for addr in socket.getaddrinfo(f"{sub}.{target_clean}", 80)
            ))
            for ip in sub_ips:
                entry = f"{ip} ({sub}.{target_clean})"
                if entry not in origin_ips:
                    origin_ips.append(entry)
                    log(f"  [ORIGIN] {entry}", Fore.RED)
        except Exception:
            pass

    results["cdn_bypass"] = list(set(origin_ips))
    if not results["cdn_bypass"]:
        log("  No origin IPs found (likely safe behind CDN)", Fore.GREEN)


# =====================================================================
# 17. HTTP METHOD FUZZING
# =====================================================================

def scan_http_methods(base_url, target_clean, results, verbose=False):
    section("HTTP METHOD FUZZING")
    method_issues = []

    methods = ["OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "PROPFIND", "MOVE", "COPY", "MKCOL"]
    test_paths = ["/", "/api", "/admin", "/api/users", "/login", "/api/config"]

    for path in test_paths:
        for method in methods:
            r = request_method(base_url + path, method, timeout=5)
            if r and 200 <= r["status"] < 400 and r["status"] not in (405, 404):
                method_issues.append(f"{method} {path} -> HTTP {r['status']}")
                color = Fore.RED if r["status"] in (200, 201) else Fore.YELLOW
                log(f"  [{method}] {path} -> {r['status']}", color)

    results["method_fuzz"] = list(set(method_issues))
    if not results["method_fuzz"]:
        log("  No risky methods found (all returned 405/404)", Fore.GREEN)


# =====================================================================
# 18. FAVICON HASH
# =====================================================================

def scan_favicon(base_url, target_clean, results, verbose=False):
    section("FAVICON HASH")

    favicon_paths = ["/favicon.ico", "/favicon.png", "/favicon.jpg", "/apple-touch-icon.png", "/static/favicon.ico"]

    known_hashes = {
        "F1758D2B3B97BCCB3AA7BDF8F5DB8E8A": "Laravel",
        "624C3CF73CFE74A3C0999E5B3E87526A": "WordPress 5.2+",
        "1E0A7B6E12D8C1E0D1F0B1E2D3C4A5B6": "Drupal",
        "A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5": "Joomla",
        "D41D8CD98F00B204E9800998ECF8427E": "Empty/Default",
    }

    for fp in favicon_paths:
        try:
            req_headers = {"User-Agent": get_random_ua()}
            r = session.get(base_url + fp, headers=req_headers, timeout=8)
            if r.status_code == 200 and len(r.content) > 0:
                md5_hash = hashlib.md5(r.content).hexdigest().upper()
                tech_match = known_hashes.get(md5_hash, "Unknown")
                log(f"  [FAVICON] {fp} -> MD5: {md5_hash} ({tech_match})", Fore.GREEN)
                results["favicon"] = {"path": fp, "md5": md5_hash, "tech": tech_match}
                return
        except Exception:
            pass

    if "favicon" not in results or not results["favicon"]:
        log("  No favicon found", Fore.YELLOW)


# =====================================================================
# 19. CLOUD BUCKET ENUMERATION
# =====================================================================

def scan_cloud_buckets(base_url, target_clean, results, verbose=False):
    section("CLOUD BUCKET ENUMERATION")
    buckets = []

    base_name = re.sub(r'\..*$', '', target_clean)
    base_name = re.sub(r'[^a-zA-Z0-9]', '', base_name)
    if len(base_name) < 2:
        base_name = re.sub(r'[^a-zA-Z0-9]', '', re.sub(r'\..*$', '', target_clean))

    year = datetime.now().year
    s3_names = [
        base_name, f"{base_name}-backup", f"{base_name}-data", f"{base_name}-assets",
        f"{base_name}-media", f"{base_name}-uploads", f"{base_name}-storage",
        f"{base_name}-prod", f"{base_name}-dev", f"{base_name}-test",
        f"{base_name}-{year}", f"{base_name}-app",
        target_clean, f"{target_clean}-backup"
    ]

    for bn in s3_names:
        s3_url = f"https://{bn}.s3.amazonaws.com"
        try:
            r = session.get(s3_url, timeout=5)
            if 'ListBucketResult' in r.text or 'Contents' in r.text:
                buckets.append(f"S3: {s3_url} (PUBLIC - listable!)")
                log(f"  [S3] {s3_url} - PUBLIC LISTABLE!", Fore.RED)
            elif r.status_code in (200, 403):
                buckets.append(f"S3: {s3_url} (HTTP {r.status_code})")
                log(f"  [S3] {s3_url} (exists, HTTP {r.status_code})", Fore.YELLOW)
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response and e.response.status_code == 403:
                buckets.append(f"S3: {s3_url} (exists, forbidden)")
                log(f"  [S3] {s3_url} (exists, forbidden)", Fore.YELLOW)

    for bn in s3_names:
        gcs_url = f"https://{bn}.storage.googleapis.com"
        try:
            r = session.get(gcs_url, timeout=5)
            if 'Contents' in r.text or 'Key' in r.text or 'Prefix' in r.text:
                buckets.append(f"GCS: {gcs_url} (PUBLIC - listable!)")
                log(f"  [GCS] {gcs_url} - PUBLIC LISTABLE!", Fore.RED)
        except Exception:
            pass

    for bn in s3_names:
        azure_url = f"https://{bn}.blob.core.windows.net"
        try:
            r = session.get(azure_url, timeout=5)
            if r.status_code in (200, 403):
                buckets.append(f"Azure: {azure_url} (HTTP {r.status_code})")
                log(f"  [AZURE] {azure_url} (exists, HTTP {r.status_code})", Fore.YELLOW)
        except Exception:
            pass

    results["cloud_buckets"] = list(set(buckets))
    if not results["cloud_buckets"]:
        log("  No public cloud buckets found", Fore.GREEN)


# =====================================================================
# 20. WEBSOCKET DETECTION
# =====================================================================

def scan_websocket(base_url, target_clean, results, verbose=False):
    section("WEBSOCKET DETECTION")
    ws_endpoints = []

    resp = request_safe(base_url, timeout=10, verbose=verbose)
    if resp is None or not resp.text:
        log("  No response", Fore.RED)
        return

    content = resp.text

    ws_patterns = [
        r'new WebSocket\(["\']([^"\']+)["\']\)',
        r'ws://[^"\';\s]+',
        r'wss://[^"\';\s]+',
        r'websocket["]?\s*["]?([^"\';\s]+)["]?',
        r'socket\.io[^"\';\s]*',
        r'SockJS[^"\';\s]*',
        r'__SOCKET__[^"\';\s]*',
        r'upgrade["\'\s]*[:=]["\'\s]*["\']websocket["\']',
    ]

    for pat in ws_patterns:
        for m in re.finditer(pat, content, re.I):
            v = m.group(0).strip()
            if v not in ws_endpoints:
                ws_endpoints.append(v)

    ws_paths = ["/ws", "/socket.io", "/websocket", "/wss", "/sockjs", "/api/ws", "/ws/v1", "/ws/v2"]
    for wp in ws_paths:
        try:
            req_headers = {"User-Agent": get_random_ua(), "Upgrade": "websocket", "Connection": "Upgrade"}
            r = session.get(base_url + wp, headers=req_headers, timeout=5)
            if r.status_code in (101, 426):
                ws_endpoints.append(f"{wp} ({r.status_code})")
                log(f"  [WS] {wp} -> HTTP {r.status_code}", Fore.YELLOW)
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response and e.response.status_code == 426:
                ws_endpoints.append(f"{wp} (426 Upgrade Required)")
                log(f"  [WS] {wp} -> 426 Upgrade Required (WebSocket exists)", Fore.YELLOW)

    results["websocket"] = list(set(ws_endpoints))
    for wse in results["websocket"]:
        log(f"  [WS] {wse}", Fore.GREEN)
    if not results["websocket"]:
        log("  No WebSocket endpoints detected", Fore.GREEN)


# =====================================================================
# 21. JWT ANALYSIS
# =====================================================================

def scan_jwt(base_url, target_clean, results, verbose=False):
    section("JWT ANALYSIS")
    jwts = []

    resp = request_safe(base_url, timeout=10, verbose=verbose)
    if resp is None:
        log("  No response", Fore.RED)
        return

    auth = resp.headers.get("Authorization", "")
    m = re.search(r'Bearer\s+(.+)', auth)
    if m:
        token = m.group(1)
        parts = token.split(".")
        if len(parts) == 3:
            jwts.append(token)
            log("  [JWT] Bearer token found in response headers", Fore.YELLOW)

    set_cookie = resp.headers.get("Set-Cookie", "")
    m = re.search(r'token=([^;]+)', set_cookie)
    if m:
        token = m.group(1)
        parts = token.split(".")
        if len(parts) == 3:
            jwts.append(token)
            log("  [JWT] Token found in cookie", Fore.YELLOW)

    if resp.text:
        jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]+=*\.[a-zA-Z0-9_-]+=*\.[a-zA-Z0-9_-]+=*')
        for m in jwt_pattern.finditer(resp.text):
            token = m.group(0)
            if token not in jwts:
                jwts.append(token)
                log("  [JWT] Found in response body", Fore.YELLOW)

    for token in jwts:
        try:
            parts = token.split(".")
            padded_h = parts[0] + "=" * (4 - len(parts[0]) % 4) if len(parts[0]) % 4 else parts[0]
            padded_p = parts[1] + "=" * (4 - len(parts[1]) % 4) if len(parts[1]) % 4 else parts[1]
            header_json = base64.urlsafe_b64decode(padded_h).decode('utf-8', errors='ignore')
            payload_json = base64.urlsafe_b64decode(padded_p).decode('utf-8', errors='ignore')

            header = json.loads(header_json)
            log(f"  [JWT] Header: {header_json}", Fore.GREEN)
            log(f"  [JWT] Payload: {payload_json}", Fore.GREEN)

            if header.get("alg") == "none":
                log("  [WARN] JWT alg='none' (vulnerable!)", Fore.RED)
            if header.get("alg", "").startswith("HS"):
                log(f"  [WARN] JWT uses symmetric algorithm ({header['alg']}) - may be crackable", Fore.YELLOW)
        except Exception:
            debug_msg(f"Could not decode JWT", verbose)

    results["jwt"] = list(set(jwts))
    if not results["jwt"]:
        log("  No JWTs found", Fore.GREEN)


# =====================================================================
# 22. LINK EXTRACTION
# =====================================================================

def scan_links(base_url, target_clean, results, verbose=False):
    section("LINK EXTRACTION")
    links = []
    internal = []

    resp = request_safe(base_url, timeout=10, verbose=verbose)
    if resp and resp.text:
        for m in re.finditer(r'href="([^"]+)"', resp.text, re.I):
            url = m.group(1)
            if url.startswith("http"):
                links.append(url)
                if target_clean in url:
                    internal.append(url)
            elif url.startswith("/"):
                internal.append(base_url.rstrip("/") + url)

    results["links"] = links
    results["internal_links"] = list(set(internal))
    log(f"Found {len(links)} total links, {len(internal)} internal", Fore.CYAN)


# =====================================================================
# SCORE CALCULATION
# =====================================================================

def update_score(results):
    penalties = 0
    if results.get("headers_missing"):
        penalties += len(results["headers_missing"]) * 5
    if results.get("vulns"):
        penalties += len(results["vulns"]) * 12
    if results.get("vulns"):
        if any("HTTP available" in v for v in results["vulns"]):
            penalties += 10
    if results.get("ssl_days_left") and results["ssl_days_left"] < 30:
        penalties += 15
    web_ports = {80, 443, 8080, 8443}
    if results.get("ports"):
        penalties += len([p for p in results["ports"] if p not in web_ports]) * 3
    if results.get("api_fuzz"):
        penalties += len(results["api_fuzz"]) * 8
    if results.get("cors"):
        penalties += len(results["cors"]) * 10
    if results.get("cdn_bypass"):
        penalties += len(results["cdn_bypass"]) * 15
    if results.get("method_fuzz"):
        penalties += len(results["method_fuzz"]) * 8
    if results.get("cloud_buckets"):
        penalties += len(results["cloud_buckets"]) * 15
    if results.get("jwt") and len(results["jwt"]) > 0:
        penalties += 5

    score = max(0, 100 - penalties)
    results["score"] = score
    return score


# =====================================================================
# JSON EXPORT
# =====================================================================

def export_json(base_url, target_clean, results, output_dir, verbose=False):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = Path(output_dir) / f"report_{target_clean}_{timestamp}.json"

    export = {
        "tool": f"Recon v{VERSION}",
        "target": target_clean,
        "url": base_url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "score": results.get("score", 0),
        "grade": grade_from_score(results.get("score", 0)),
        "ip": results.get("ip"),
        "http_status": results.get("http_status"),
        "page_size": results.get("page_size"),
        "tech": results.get("tech"),
        "headers_present": results.get("headers_present"),
        "headers_missing": results.get("headers_missing"),
        "waf": results.get("waf"),
        "tech_fp": results.get("tech_fp"),
        "cms": results.get("cms"),
        "dirs": results.get("dirs"),
        "subdomains": results.get("subdomains"),
        "ports": results.get("ports"),
        "dns": results.get("dns"),
        "ssl": results.get("ssl"),
        "ssl_days_left": results.get("ssl_days_left"),
        "vulns": results.get("vulns"),
        "emails": results.get("emails"),
        "links": {"total": len(results.get("links", [])), "internal": len(results.get("internal_links", []))},
        "api_fuzz": results.get("api_fuzz"),
        "wayback": results.get("wayback"),
        "js_endpoints": results.get("js_endpoints"),
        "api_keys": results.get("api_keys"),
        "js_files": results.get("js_files"),
        "cors": results.get("cors"),
        "cdn_bypass": results.get("cdn_bypass"),
        "method_fuzz": results.get("method_fuzz"),
        "favicon": results.get("favicon"),
        "cloud_buckets": results.get("cloud_buckets"),
        "websocket": results.get("websocket"),
        "jwt": results.get("jwt"),
    }

    json_file.write_text(json.dumps(export, indent=2, default=str), encoding="utf-8")
    log(f"  [JSON] {json_file}", Fore.GREEN)
    return str(json_file)


def grade_from_score(score):
    if score >= 80:
        return "A"
    elif score >= 60:
        return "B"
    elif score >= 40:
        return "C"
    elif score >= 20:
        return "D"
    return "E"


# =====================================================================
# HTML REPORT
# =====================================================================

def _build_section(title, items, css_class="", empty_msg=""):
    if not items:
        if empty_msg:
            return f"<div class='section'><h2>{title}</h2><p class='good'>{empty_msg}</p></div>"
        return ""
    html = f"<div class='section'><h2>{title}</h2><ul>"
    for item in items:
        cls = f" class='{css_class}'" if css_class else ""
        html += f"<li{cls}>{item}</li>"
    html += "</ul></div>"
    return html


def _build_kv_section(title, data, key_label="", val_label=""):
    if not data:
        return ""
    html = f"<div class='section'><h2>{title}</h2><ul>"
    for k, vals in data.items():
        for v in (vals if isinstance(vals, list) else [vals]):
            html += f"<li><b>{k}</b>: {v}</li>"
    html += "</ul></div>"
    return html


def _build_link_section(title, items):
    if not items:
        return ""
    html = f"<div class='section'><h2>{title}</h2><ul>"
    for l in items:
        html += f"<li><a href='{l}' style='color:#8888ff'>{l}</a></li>"
    html += "</ul></div>"
    return html


def generate_report(base_url, target_clean, results, output_dir, verbose=False):
    section("REPORT GENERATION")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = Path(output_dir) / f"report_{target_clean}_{timestamp}.html"

    score = results.get("score", 0)
    grade = grade_from_score(score)
    score_class = "good" if score >= 60 else ("warn" if score >= 40 else "bad")

    headers_html = "<ul>"
    if results.get("headers_present"):
        for h in results["headers_present"]:
            headers_html += f"<li class='good'>[OK] {h}</li>"
    if results.get("headers_missing"):
        for h in results["headers_missing"]:
            headers_html += f"<li class='bad'>[MISSING] {h}</li>"
    headers_html += "</ul>"

    ssl_html = ""
    if results.get("ssl"):
        s = results["ssl"]
        ssl_html = f"""<div class='section'><h2>SSL/TLS</h2><ul>
<li>Subject: {s.get('subject', 'N/A')}</li>
<li>Issuer: {s.get('issuer', 'N/A')}</li>
<li>Valid: {s.get('valid_from', 'N/A')} -> {s.get('valid_to', 'N/A')}</li>
<li>Key: {s.get('algorithm', 'N/A')} ({s.get('key_size', 0)} bits)</li>
<li>Expires in: {results.get('ssl_days_left', 'N/A')} days</li>
</ul></div>"""

    favicon_html = ""
    if results.get("favicon"):
        f = results["favicon"]
        favicon_html = f"<div class='section'><h2>Favicon</h2><ul><li>Path: {f.get('path', 'N/A')}</li><li>MD5: {f.get('md5', 'N/A')}</li><li>Match: {f.get('tech', 'N/A')}</li></ul></div>"

    code_chart_html = ""
    if results.get("dirs"):
        code_counts = {}
        for d in results["dirs"]:
            c = str(d["code"])
            code_counts[c] = code_counts.get(c, 0) + 1
        if code_counts:
            max_c = max(code_counts.values())
            code_chart_html = "<div class='section'><h2>Directory HTTP Code Distribution</h2>"
            for k in sorted(code_counts.keys(), key=int):
                pct = round(code_counts[k] / max_c * 100)
                bar_color = "#00ff88" if 200 <= int(k) < 300 else "#ffd700" if 300 <= int(k) < 400 else "#ff4444"
                code_chart_html += f"<div class='code-row'><span class='code-label'>{k}</span><div class='bar-wrapper'><div class='bar' style='width:{pct}px;background:{bar_color}'></div></div><span class='code-count'>{code_counts[k]}x</span></div>"
            code_chart_html += "</div>"

    ip_html = ""
    if results.get("ip"):
        ip_html = f"<tr><th>IP Address</th><td>{', '.join(results['ip'])}</td></tr>"
    tech_row_html = ""
    if results.get("tech"):
        tech_row_html = f"<tr><th>Tech (Headers)</th><td>{', '.join(results['tech'])}</td></tr>"

    waf_html = _build_section("WAF Detection", results.get("waf"), "info")
    tech_html = _build_section("Technology Stack", results.get("tech_fp"))
    cms_html = _build_section("CMS Detection", results.get("cms"))
    dns_html = _build_kv_section("DNS Records", results.get("dns"))
    dirs_html = _build_section("Discovered Paths", [f"[{d['code']}] {d['path']}" for d in (results.get("dirs") or [])], "warn")
    sub_html = _build_section("Subdomains", [f"{s['url']} ({s['status']})" for s in (results.get("subdomains") or [])], "info")
    port_html = _build_section("Open Ports", [f"Port {p} ({PORT_SERVICE_MAP.get(p, 'Unknown')})" for p in (results.get("ports") or [])], "warn")
    vuln_html = _build_section("Vulnerabilities Found", results.get("vulns"), "bad", "No vulnerabilities detected in basic scan")
    email_html = _build_section("Emails Found", results.get("emails"))
    api_html = _build_section("API / GraphQL", results.get("api_fuzz"), "warn")
    js_html = _build_section("JS Endpoints", results.get("js_endpoints"))
    key_html = _build_section("API Keys / Secrets Found!", results.get("api_keys"), "bad")
    cors_html = _build_section("CORS Issues", results.get("cors"), "bad")
    cdn_html = _build_section("Origin IP (CDN Bypass)", results.get("cdn_bypass"), "warn")
    method_html = _build_section("HTTP Method Fuzzing", results.get("method_fuzz"), "warn")
    bucket_html = _build_section("Cloud Buckets", results.get("cloud_buckets"), "bad")
    ws_html = _build_section("WebSocket Endpoints", results.get("websocket"))
    jwt_html = _build_section("JWT Tokens Found", [f"{t[:80]}..." for t in (results.get("jwt") or [])], "warn")
    wayback_html = _build_section("Wayback Machine (last 20)", [f"{w['date']} [{w['status']}] {w['url']}" for w in (results.get("wayback") or [])])
    link_html = _build_link_section("Internal Links", results.get("internal_links"))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report - {target_clean}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',sans-serif; background:#0f0f1a; color:#e0e0e0; padding:20px; }}
h1 {{ color:#00d4ff; border-bottom:2px solid #00d4ff; padding-bottom:10px; font-size:28px; }}
h2 {{ color:#ffd700; margin:20px 0 10px; padding:8px; background:#1a1a2e; border-radius:5px; font-size:18px; }}
.section {{ background:#1a1a2e; border-radius:8px; padding:15px; margin:10px 0; }}
.good {{ color:#00ff88; }} .warn {{ color:#ffd700; }} .bad {{ color:#ff4444; }} .info {{ color:#8888ff; }}
ul {{ list-style:none; padding:0; }}
li {{ padding:4px 0; border-bottom:1px solid #2a2a3e; font-size:13px; }}
.footer {{ text-align:center; margin-top:30px; color:#666; font-size:12px; }}
table {{ width:100%; border-collapse:collapse; margin:10px 0; }}
th,td {{ padding:8px; text-align:left; border-bottom:1px solid #2a2a3e; }}
th {{ background:#2a2a3e; color:#ffd700; }}
.score-box {{ display:inline-block; padding:10px 20px; border-radius:5px; font-size:24px; font-weight:bold; margin:10px 0; }}
.code-row {{ display:flex; align-items:center; margin:4px 0; gap:8px }}
.code-label {{ width:40px; font-size:12px; color:#94a3b8; text-align:right }}
.code-count {{ font-size:12px; color:#94a3b8; white-space:nowrap }}
.bar-wrapper {{ flex:1; height:20px; background:#2a2a3e; border-radius:4px; overflow:hidden }}
.bar {{ height:100%; min-width:4px; border-radius:4px; transition:width 0.2s }}
.score-bar {{ height:8px; background:#2a2a3e; border-radius:4px; overflow:hidden; margin:8px 0 }}
.score-fill {{ height:100%; border-radius:4px; transition:width 0.5s }}
.summary-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:10px; }}
.meta {{ color:#888; font-size:12px; }}
</style>
</head>
<body>
<h1>Recon Report v{VERSION}: {target_clean}</h1>
<p class='meta'>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

<div class="section">
<h2>Summary</h2>
<div class='score-bar'><div class='score-fill {score_class}' style='width:{score}%' title='Score: {score}/100'></div></div>
<table>
<tr><th>Target</th><td>{target_clean}</td></tr>
{ip_html}
{tech_row_html}
<tr><th>HTTP Status</th><td>{results.get("http_status", "N/A")}</td></tr>
<tr><th>Page Size</th><td>{results.get("page_size", 0)} bytes</td></tr>
</table>
<div class='score-box {score_class}'>Security Score: {score}/100 ({grade})</div>
</div>

<div class='section'><h2>Security Headers</h2>
<p>Present: {len(results.get("headers_present", []))} / {len(results.get("headers_present", [])) + len(results.get("headers_missing", []))}</p>
{headers_html}
</div>
{waf_html}
{tech_html}
{cms_html}
{dns_html}
{ssl_html}
{dirs_html}
{sub_html}
{port_html}
{vuln_html}
{api_html}
{js_html}
{key_html}
{cors_html}
{cdn_html}
{method_html}
{favicon_html}
{bucket_html}
{ws_html}
{jwt_html}
{email_html}
{link_html}
{code_chart_html}
{wayback_html}

<div class='footer'>
<p>Generated by Recon Automation Tool v{VERSION}</p>
<p>Web Security Audit</p>
</div>
</body>
</html>"""

    report_file.write_text(html, encoding="utf-8")
    log(f"  [HTML] {report_file}", Fore.GREEN)
    return str(report_file)


# =====================================================================
# MAIN
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"Recon Automation Tool v{VERSION} - Universal Web Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py -t example.com
  python recon.py -t example.com --full --verbose
  python recon.py -t example.com --full --json --wordlist mydirs.txt --depth 2
  python recon.py -T targets.txt
        """
    )
    parser.add_argument("-t", "--target", help="Target domain or URL to scan")
    parser.add_argument("-T", "--target-file", help="File containing list of targets (one per line)")
    parser.add_argument("--full", action="store_true", help="Full scan (+ ports, subdomains)")
    parser.add_argument("--json", action="store_true", help="Export results as JSON")
    parser.add_argument("-o", "--output", default="./recon", help="Output directory for reports (default: ./recon)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file for directory scan")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Directory recursion depth (default: 1, max: 3)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug output")

    args = parser.parse_args()

    if not args.target and not args.target_file:
        print(f"{Fore.YELLOW}Usage: python recon.py -t example.com [--full] [--json]{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}       python recon.py -T targets.txt{Style.RESET_ALL}")
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    custom_wordlist = None
    if args.wordlist:
        wl_path = Path(args.wordlist)
        if wl_path.exists():
            custom_wordlist = [
                line.strip() for line in wl_path.read_text().splitlines()
                if line.strip()
            ]
            log(f"Loaded custom wordlist: {len(custom_wordlist)} paths", Fore.CYAN)
        else:
            log(f"Wordlist file not found: {args.wordlist} (using built-in)", Fore.YELLOW)

    targets = []
    if args.target_file:
        tf_path = Path(args.target_file)
        if tf_path.exists():
            targets = [
                clean_target(line) for line in tf_path.read_text().splitlines()
                if line.strip()
            ]
        else:
            log(f"File not found: {args.target_file}", Fore.RED)
            sys.exit(1)
    else:
        targets = [clean_target(args.target)]

    for t in targets:
        base_url = to_url(t)
        clean_t = clean_target(t)

        print(f"\n{Fore.CYAN}============================================================")
        print(f" Scanning: {t}")
        print(f" Base URL: {base_url}")
        print(f"============================================================{Style.RESET_ALL}")

        results = {
            "http_status": 0, "page_size": 0, "score": 0,
            "headers_present": [], "headers_missing": [], "tech": [],
            "waf": [], "tech_fp": [], "ip": [], "dirs": [],
            "subdomains": [], "ports": [], "dns": {},
            "ssl": {}, "ssl_days_left": 0, "vulns": [],
            "cms": [], "emails": [], "links": [], "internal_links": [],
            "api_fuzz": [], "wayback": [], "js_endpoints": [],
            "api_keys": [], "js_files": [], "cors": [],
            "cdn_bypass": [], "method_fuzz": [], "favicon": {},
            "cloud_buckets": [], "websocket": [], "jwt": [],
        }

        scan_ip(base_url, clean_t, results, verbose=args.verbose)
        scan_security_headers(base_url, clean_t, results, verbose=args.verbose)
        scan_directories(base_url, clean_t, results, depth=min(args.depth, 3), custom_wordlist=custom_wordlist, verbose=args.verbose)
        scan_cms(base_url, clean_t, results, verbose=args.verbose)
        scan_emails(base_url, clean_t, results, verbose=args.verbose)
        scan_links(base_url, clean_t, results, verbose=args.verbose)
        scan_vulns(base_url, clean_t, results, verbose=args.verbose)
        scan_tech_fingerprint(base_url, clean_t, results, verbose=args.verbose)
        scan_dns(base_url, clean_t, results, verbose=args.verbose)
        scan_ssl(base_url, clean_t, results, verbose=args.verbose)
        scan_wayback(base_url, clean_t, results, verbose=args.verbose)
        scan_api_fuzz(base_url, clean_t, results, verbose=args.verbose)

        scan_js_extract(base_url, clean_t, results, verbose=args.verbose)
        scan_cors(base_url, clean_t, results, verbose=args.verbose)
        scan_cdn_bypass(base_url, clean_t, results, verbose=args.verbose)
        scan_http_methods(base_url, clean_t, results, verbose=args.verbose)
        scan_favicon(base_url, clean_t, results, verbose=args.verbose)
        scan_cloud_buckets(base_url, clean_t, results, verbose=args.verbose)
        scan_websocket(base_url, clean_t, results, verbose=args.verbose)
        scan_jwt(base_url, clean_t, results, verbose=args.verbose)

        if args.full:
            scan_ports(base_url, clean_t, results, verbose=args.verbose)
            scan_subdomains(base_url, clean_t, results, verbose=args.verbose)

        update_score(results)
        generate_report(base_url, clean_t, results, output_dir, verbose=args.verbose)
        if args.json:
            export_json(base_url, clean_t, results, output_dir, verbose=args.verbose)

        log(f"Scan complete for {t}", Fore.GREEN)

    log("All scans completed.", Fore.GREEN)


if __name__ == "__main__":
    main()
