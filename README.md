# Recon Automation Tool

Custom PowerShell recon scanner for security auditing.

## Features
- Security headers check (HSTS, CSP, XFO, etc.) + scoring
- Directory busting (92 common paths)
- Subdomain enumeration (76 common subdomains)
- Port scanning (35 common ports via TCP connect)
- Vulnerability checks (.env, .git, backup files, actuator, etc.)
- CMS detection (WordPress, Joomla, Drupal, Laravel)
- Email extraction from pages
- Link extraction
- IP resolution
- HTML report generation with security score

## Usage
```powershell
.\recon.ps1 -Target example.com -Quick
.\recon.ps1 -Target example.com -Full
.\recon.ps1 -TargetFile targets.txt -Quick
```

## Flags
- `-Target`  Domain/URL to scan
- `-TargetFile`  File containing list of targets
- `-Quick`  Basic scan (no port scan or subdomain enumeration)
- `-Full`  Full scan (all modules)
- `-OutputDir`  Output directory (default: ./recon)

## Requirements
- Windows PowerShell 5.1+ or PowerShell 7+
- .NET Framework (built-in on Windows)
- No external dependencies

## Output
- Console output with real-time logging
- HTML report with security score (A-E)
- Raw scan logs (.txt files)
