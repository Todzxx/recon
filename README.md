# Recon Automation Tool v5.0

Multi-module recon scanner di-Python-kan dari versi PowerShell asli.

## Fitur

### Core Modules
- Security headers check (HSTS, CSP, XFO, etc.) + scoring
- Directory busting (425+ paths, concurrent via ThreadPoolExecutor)
- Subdomain enumeration (200+ subdomains, concurrent)
- Port scanning (31 ports via TCP connect, concurrent)
- DNS enumeration (A, MX, NS, TXT, CNAME, SOA)
- SSL/TLS analysis (cert, expiry, key exchange)
- WAF detection (Cloudflare, Akamai, Sucuri, Incapsula)
- CMS detection (WordPress, Joomla, Drupal, Laravel, Magento)
- Tech fingerprinting (React, Vue, Angular, Next.js, Tailwind, etc.)
- Vulnerability checks (.env, .git, actuator, SQLi, XSS, LFI)
- Wayback machine integration
- API fuzzing (GraphQL introspection, docs, parameter fuzz)
- Email + link extraction
- JS endpoint extraction & API key discovery
- CORS misconfiguration checker
- CDN origin IP bypass
- HTTP method fuzzing (OPTIONS, PUT, DELETE, TRACE, etc.)
- Favicon hash matching
- Cloud bucket enumeration (S3, GCS, Azure)
- WebSocket detection
- JWT analysis (detect + decode + alg check)
- Directory recursion (depth 1-3)
- Custom wordlist support
- HTML report with security score (A-E)
- JSON export

## Usage

```bash
python recon.py -t example.com
python recon.py -t example.com --full --verbose
python recon.py -t example.com --full --json --wordlist mydirs.txt --depth 2
python recon.py -t example.com --full --nmap --nmap-args "-sV -sC --top-ports 100"
python recon.py -T targets.txt
```

## Parameters

| Arg | Description |
|-----|-------------|
| `-t, --target` | Domain/URL to scan |
| `-T, --target-file` | File containing list of targets |
| `--full` | Full scan (+ ports, subdomains) |
| `--json` | Export results as JSON |
| `-o, --output` | Output directory (default: `./recon`) |
| `-w, --wordlist` | Custom directory wordlist file |
| `-d, --depth` | Directory recursion depth (1-3, default: 1) |
| `--nmap` | Use nmap for port scanning (requires nmap installed) |
| `--nmap-args` | Extra nmap arguments (default: `-sV -sC --min-rate=500 --max-retries=2`) |
| `-v, --verbose` | Enable debug output |

## Requirements
- Python 3.8+
- `requests`, `dnspython`, `colorama`

Install: `pip install requests dnspython colorama`

## Output
- Console output with real-time colored logging
- HTML report with security score (A-E)
- JSON export (optional)
