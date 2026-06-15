# Recon Automation Tool v5.0

Custom PowerShell recon scanner for security auditing.

## Features

### v5.0 Improvements
- .NET `HttpWebRequest` (replaces `Invoke-WebRequest` cmdlet) — reliable SSL, no self-signed cert issues
- `[System.Net.ServicePointManager]::ServerCertificateValidationCallback` — universal SSL bypass
- Fixed `$using:` bug in runspace pools — parallel directory/subdomain/port scans now work correctly
- Concurrent vulnerability scanning — 55+ sensitive paths checked in parallel
- Rate limiting awareness — 429 auto-detection + Retry-After header + exponential backoff
- HTML report bar charts — HTTP code distribution, security headers score bar
- Rate limited retry — 3 retries on failure with exponential backoff

### Core (v1-v3)
- Security headers check (HSTS, CSP, XFO, etc.) + scoring
- Directory busting (425 paths, concurrent)
- Subdomain enumeration (313 subdomains, concurrent)
- Port scanning (35 ports via TCP connect, concurrent)
- DNS enumeration (A, MX, NS, TXT, CNAME, SOA)
- SSL/TLS analysis (cert, expiry, key exchange)
- WAF detection (Cloudflare, Akamai, Sucuri, Incapsula)
- CMS detection (WordPress, Joomla, Drupal, Laravel, Magento)
- Tech fingerprinting (React, Vue, Angular, Next.js, Tailwind, etc.)
- Vulnerability checks (.env, .git, actuator, SQLi, XSS, LFI)
- Wayback machine integration
- API fuzzing (GraphQL introspection, docs, parameter fuzz)
- Email + link extraction
- HTML report with security score (A-E)

### New in v4.0
- **JS Endpoint Extraction** — finds API endpoints, paths, and secrets from JS files
- **CORS Misconfiguration Checker** — tests for overly permissive CORS policies
- **CDN Origin IP Bypass** — attempts to find real IP behind Cloudflare/Akamai
- **HTTP Method Fuzzing** — tests OPTIONS, PUT, PATCH, DELETE, TRACE, etc.
- **Favicon Hash** — computes MD5 and matches against known tech
- **Cloud Bucket Enumeration** — checks for public S3, GCS, and Azure blobs
- **WebSocket Detection** — finds WebSocket endpoints in HTML/JS + path fuzzing
- **JWT Analysis** — detects and decodes JSON Web Tokens, checks alg
- **Directory Recursion** — `-Depth 2` or `-Depth 3` for recursive directory scanning
- **Custom Wordlist** — `-WordlistFile` for your own directory paths
- **Auto-Retry on 429** — exponential backoff when rate limited
- **Verbose/Debug Mode** — `-Verbose` for detailed output
- **Concurrent Execution** — 20-35x parallel via RunspacePool

## Usage

```powershell
.\recon.ps1 -Target example.com -Quick
.\recon.ps1 -Target example.com -Full -Verbose
.\recon.ps1 -Target example.com -Full -Json -WordlistFile mydirs.txt -Depth 2
.\recon.ps1 -Target examle.com -Full -Nmap -NmapArgs "-sV -sC --top-ports 100 --min-rate=1000"
.\recon.ps1 -TargetFile targets.txt -Quick
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-Target` | Domain/URL to scan |
| `-TargetFile` | File containing list of targets |
| `-Quick` | Quick scan (basic modules) |
| `-Full` | Full scan (+ ports, subdomains) |
| `-Json` | Export results as JSON |
| `-OutputDir` | Output directory (default: ./recon) |
| `-WordlistFile` | Custom directory wordlist file |
| `-Depth` | Directory recursion depth (1-3, default: 1) |
| `-Verbose` | Enable debug output |
| `-Nmap` | Use nmap for port scanning (requires nmap installed) |
| `-NmapArgs` | Extra nmap args (default: `-sV -sC --min-rate=500 --max-retries=2`) |

## Requirements
- Windows PowerShell 5.1+
- .NET Framework (built-in on Windows)
- Optional: nmap 7.x for `-Nmap` port scanning

## Output
- Console output with real-time logging
- HTML report with security score (A-E)
- JSON export (optional)
- Raw nmap XML (in output dir when `-Nmap` used)
