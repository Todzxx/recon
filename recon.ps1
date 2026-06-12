<#
.SYNOPSIS
    Recon Automation Tool - Web Security Audit
.DESCRIPTION
    Multi-module recon scanner: security headers, directory busting, subdomains,
    port scanning, vulnerability detection, CMS detection, email extraction, JWT analysis
.PARAMETER Target
    Target domain or URL to scan
.PARAMETER TargetFile
    File containing list of targets (one per line)
.PARAMETER Quick
    Quick scan (no port scan or subdomain enumeration)
.PARAMETER Full
    Full scan (all modules including port scan and subdomain enumeration)
.PARAMETER OutputDir
    Output directory for reports
.EXAMPLE
    .\recon.ps1 -Target example.com -Quick
    .\recon.ps1 -Target example.com -Full
    .\recon.ps1 -TargetFile targets.txt -Quick
#>

param(
    [string]$Target,
    [string]$TargetFile,
    [switch]$Quick,
    [switch]$Full,
    [string]$OutputDir = "D:\TUGAS\output\recon"
)

# =====================================================================
# CONFIG
# =====================================================================
$Script:wordlist = @("admin","login","api","wp-admin","wp-content","backup","config",".env","test","dashboard","uploads","assets","static","js","css","images","img","vendor","node_modules","src","app","public","private","temp","logs","error","404","500","robots.txt","sitemap.xml","cgi-bin","includes","modules","plugins","themes","core","data","db","database","sql","phpmyadmin","administrator","panel","manager","management","console","controlpanel","cpanel","webmail","mail","owa","exchange","autodiscover","remote","desktop","rdp","vpn","proxy","socks","gateway","portal","intranet","extranet","help","support","chat","contact","about","faq","terms","privacy","license","swagger","docs","api-docs","api/v1","api/v2","graphql","soap","rest","api/auth","api/users","api/admin","api/config","api/status","api/health","api/metrics","api/logs","api/debug","api/.env","api/swagger","api/docs")

$Script:subdomainList = @("www","mail","remote","blog","shop","api","dev","test","admin","cdn","static","assets","images","img","video","media","download","files","ftp","smtp","pop3","imap","webmail","owa","exchange","vpn","proxy","secure","login","portal","app","mobile","m","www2","www3","backup","staging","stage","beta","alpha","demo","sandbox","sandpit","dev2","dev3","test2","monitor","status","help","support","docs","wiki","forum","community","chat","board","git","svn","jenkins","jira","confluence","wiki","pma","phpmyadmin","sql","db","database","config","configurator","setup","install","license","api","gateway","services","service")

$Script:commonPorts = @(21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,8080,8443,9000,9090,10000,11211,27017)

$Script:userAgents = @(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "curl/8.4.0"
)

# =====================================================================
# HELPER FUNCTIONS
# =====================================================================
function Write-Banner {
    Clear-Host
    $banner = @"

    RECON AUTOMATION TOOL v3.0
    Universal Security Audit Tool
    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Log {
    param([string]$Msg, [string]$Color = "White")
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Msg" -ForegroundColor $Color
}

function Section {
    param([string]$Name)
    Write-Host "`n====== $Name ======" -ForegroundColor Yellow
}

function Get-CleanTarget {
    param([string]$t)
    $t = $t.Trim().ToLower()
    $t = $t -replace '^https?://', ''
    $t = $t -replace '/.*$', ''
    return $t
}

function Get-Url {
    param([string]$t)
    $t = $t.Trim().ToLower()
    if ($t -notlike 'http*') { $t = "https://$t" }
    return $t
}

function Invoke-WebRequestSafe {
    param([string]$Url, [int]$TimeoutSec = 15)
    try {
        $ua = $Script:userAgents | Get-Random
        $resp = Invoke-WebRequest -Uri $Url -UserAgent $ua -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        return $resp
    } catch {
        return $null
    }
}

function Test-Port {
    param([string]$Hostname, [int]$Port, [int]$TimeoutMs = 3000)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($wait -and $tcp.Connected) {
            $tcp.EndConnect($async) | Out-Null
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch {
        return $false
    }
}

# =====================================================================
# 1. SECURITY HEADERS SCAN
# =====================================================================
function Scan-SecurityHeaders {
    param($baseUrl, $targetClean, $results)
    Section "SECURITY HEADERS"
    $headersToCheck = @{
        "Strict-Transport-Security" = "HSTS"
        "Content-Security-Policy" = "CSP"
        "X-Content-Type-Options" = "X-Content-Type-Options"
        "X-Frame-Options" = "X-Frame-Options"
        "X-XSS-Protection" = "X-XSS-Protection"
        "Referrer-Policy" = "Referrer-Policy"
        "Permissions-Policy" = "Permissions-Policy"
        "Access-Control-Allow-Origin" = "CORS"
        "Set-Cookie" = "Secure/HttpOnly Cookies"
    }
    $resp = Invoke-WebRequestSafe $baseUrl
    if (-not $resp) {
        Log "Failed to fetch $baseUrl" "Red"
        return
    }
    $results.http_status = [int]$resp.StatusCode
    $results.page_size = if ($resp.RawContentStreamHandle) { $resp.RawContentStreamHandle.Length } else { $resp.Content.Length }
    $present = @()
    $missing = @()
    foreach ($h in $headersToCheck.Keys) {
        if ($resp.Headers.ContainsKey($h)) {
            $present += $headersToCheck[$h]
            Log "  [OK] $($headersToCheck[$h])" "Green"
        } else {
            $missing += $headersToCheck[$h]
            Log "  [WARN] $($headersToCheck[$h]) missing" "Yellow"
        }
    }
    $results.headers_present = $present
    $results.headers_missing = $missing
    
    # Tech detection
    $tech = @()
    if ($resp.Headers.ContainsKey("Server")) { $tech += "Server: $($resp.Headers['Server'])" }
    if ($resp.Headers.ContainsKey("X-Powered-By")) { $tech += "$($resp.Headers['X-Powered-By'])" }
    if ($resp.Headers.ContainsKey("X-Generator")) { $tech += "$($resp.Headers['X-Generator'])" }
    $results.tech = $tech
    
    # Score
    $score = [math]::Round(($present.Count / $headersToCheck.Count) * 100, 0)
    $results.score = $score
    Log "Security Score: $score/100" "Green"
}

# =====================================================================
# 2. DIRECTORY SCAN
# =====================================================================
function Scan-Directories {
    param($baseUrl, $targetClean, $results)
    Section "DIRECTORY SCAN"
    $found = @()
    $total = $Script:wordlist.Count
    $i = 0
    foreach ($path in $Script:wordlist) {
        $i++
        $url = "$baseUrl/$path"
        Log "  [$i/$total] Checking $url" "Gray"
        $resp = Invoke-WebRequestSafe $url
        if ($resp) {
            $code = [int]$resp.StatusCode
            if ($code -ne 404) {
                $color = if ($code -le 400) { "Green" } else { "Yellow" }
                Log "  [FOUND] $url ($code)" $color
                $found += @{path = $url; code = $code}
            }
        }
        if ($Quick -and $found.Count -ge 5) { break }
    }
    $results.dirs = $found
    Log "Found $($found.Count) accessible paths" "Cyan"
}

# =====================================================================
# 3. SUBDOMAIN ENUMERATION
# =====================================================================
function Scan-Subdomains {
    param($baseUrl, $targetClean, $results)
    Section "SUBDOMAIN ENUMERATION"
    $found = @()
    $total = $Script:subdomainList.Count
    $i = 0
    foreach ($sub in $Script:subdomainList) {
        $i++
        $url = "https://$sub.$targetClean"
        Log "  [$i/$total] Checking $sub.$targetClean" "Gray"
        $resp = Invoke-WebRequestSafe $url
        if ($resp -and [int]$resp.StatusCode -ne 404) {
            Log "  [FOUND] $sub.$targetClean ($([int]$resp.StatusCode))" "Green"
            $found += $url
        }
    }
    $results.subdomains = $found
    Log "Found $($found.Count) subdomains" "Cyan"
}

# =====================================================================
# 4. PORT SCAN
# =====================================================================
function Scan-Ports {
    param($baseUrl, $targetClean, $results)
    Section "PORT SCAN"
    $open = @()
    $total = $Script:commonPorts.Count
    foreach ($port in $Script:commonPorts) {
        Log "  Testing port $port" "Gray"
        if (Test-Port $targetClean $port) {
            Log "  [OPEN] Port $port is open" "Red"
            $open += $port
        }
    }
    $results.ports = $open
    Log "Found $($open.Count) open ports" "Cyan"
}

# =====================================================================
# 5. VULNERABILITY CHECKS
# =====================================================================
function Scan-Vulns {
    param($baseUrl, $targetClean, $results)
    Section "VULNERABILITY CHECKS"
    $vulns = @()
    
    # Check for common vulnerable paths
    $vulnPaths = @("/.env", "/wp-config.php.bak", "/config.php.bak", "/config.bak", "/db.sql", "/dump.sql", "/backup.sql", "/.git/config", "/.svn/entries", "/crossdomain.xml", "/clientaccesspolicy.xml", "/phpinfo.php", "/info.php", "/debug", "/api/debug", "/actuator", "/actuator/health", "/swagger-ui.html", "/api/swagger", "/graphql?query={__schema{types{name}}}")
    
    foreach ($path in $vulnPaths) {
        $url = "$baseUrl$path"
        Log "  Checking $url" "Gray"
        $resp = Invoke-WebRequestSafe $url
        if ($resp -and [int]$resp.StatusCode -lt 400) {
            Log "  [VULN] $url returned $([int]$resp.StatusCode)" "Red"
            $vulns += "$path ($([int]$resp.StatusCode))"
        }
    }
    
    # Check for insecure protocols
    $httpUrl = $baseUrl -replace '^https://', 'http://'
    if ($httpUrl -ne $baseUrl) {
        $resp = Invoke-WebRequestSafe $httpUrl
        if ($resp -and [int]$resp.StatusCode -lt 400) {
            Log "  [VULN] HTTP site accessible (no forced HTTPS)" "Red"
            $vulns += "HTTP available (no redirect to HTTPS)"
        }
    }
    
    $results.vulns = $vulns
    $color = if ($vulns.Count -gt 0) { "Red" } else { "Green" }
    Log "Found $($vulns.Count) potential vulnerabilities" $color
}

# =====================================================================
# 6. CMS DETECTION
# =====================================================================
function Scan-CMS {
    param($baseUrl, $targetClean, $results)
    Section "CMS DETECTION"
    $cms = @()
    
    # WordPress
    $wpChecks = @("/wp-content/", "/wp-admin/", "/wp-includes/", "/wp-json/", "/xmlrpc.php")
    $wpMatch = 0
    foreach ($p in $wpChecks) {
        $resp = Invoke-WebRequestSafe "$baseUrl$p"
        if ($resp -and [int]$resp.StatusCode -ne 404) { $wpMatch++ }
    }
    if ($wpMatch -ge 2) { $cms += "WordPress (confidence: high)" }
    
    # Joomla
    $joomlaChecks = @("/components/", "/modules/", "/templates/", "/administrator/", "/media/")
    $jMatch = 0
    foreach ($p in $joomlaChecks) {
        $resp = Invoke-WebRequestSafe "$baseUrl$p"
        if ($resp -and [int]$resp.StatusCode -ne 404) { $jMatch++ }
    }
    if ($jMatch -ge 2) { $cms += "Joomla (confidence: high)" }
    
    # Drupal
    $drupalChecks = @("/sites/", "/core/", "/modules/", "/themes/", "/node/")
    $dMatch = 0
    foreach ($p in $drupalChecks) {
        $resp = Invoke-WebRequestSafe "$baseUrl$p"
        if ($resp -and [int]$resp.StatusCode -ne 404) { $dMatch++ }
    }
    if ($dMatch -ge 2) { $cms += "Drupal (confidence: high)" }
    
    # Laravel
    $resp = Invoke-WebRequestSafe "$baseUrl"
    if ($resp -and $resp.Content -match 'laravel|csrf-token|livewire') {
        $cms += "Laravel (detected via meta/cookies)"
    }
    
    $results.cms = $cms
    if ($cms.Count -gt 0) {
        foreach ($c in $cms) { Log "  [CMS] $c" "Green" }
    } else {
        Log "  No CMS detected" "Yellow"
    }
}

# =====================================================================
# 7. EMAIL EXTRACTION
# =====================================================================
function Scan-Emails {
    param($baseUrl, $targetClean, $results)
    Section "EMAIL EXTRACTION"
    $emails = @()
    
    $pagesToCheck = @("$baseUrl", "$baseUrl/contact", "$baseUrl/about", "$baseUrl/team", "$baseUrl/people", "$baseUrl/staff", "$baseUrl/directory")
    $emailRegex = [regex]'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    
    foreach ($page in $pagesToCheck) {
        $resp = Invoke-WebRequestSafe $page
        if ($resp -and $resp.Content) {
            $found = $emailRegex.Matches($resp.Content) | ForEach-Object { $_.Value.ToLower() } | Where-Object { $_ -notmatch '\.png|\.jpg|\.css|example\.com|\.local|\.test' } | Sort-Object -Unique
            foreach ($e in $found) {
                if ($e -notin $emails) {
                    Log "  [EMAIL] $e" "Green"
                    $emails += $e
                }
            }
        }
    }
    
    $results.emails = $emails
    Log "Found $($emails.Count) email addresses" "Cyan"
}

# =====================================================================
# 8. LINK EXTRACTION
# =====================================================================
function Scan-Links {
    param($baseUrl, $targetClean, $results)
    Section "LINK EXTRACTION"
    $links = @()
    $internal = @()
    
    $resp = Invoke-WebRequestSafe $baseUrl
    if ($resp -and $resp.Content) {
        $linkRegex = [regex]'href="([^"]+)"'
        $matches = $linkRegex.Matches($resp.Content)
        foreach ($m in $matches) {
            $url = $m.Groups[1].Value
            if ($url -match '^https?://') {
                $links += $url
                if ($url -match $targetClean) {
                    $internal += $url
                }
            } elseif ($url -match '^/') {
                $internal += "$baseUrl$url"
            }
        }
    }
    
    $results.links = $links
    $results.internal_links = $internal
    Log "Found $($links.Count) total links, $($internal.Count) internal" "Cyan"
}

# =====================================================================
# 9. IP RESOLUTION
# =====================================================================
function Scan-IP {
    param($baseUrl, $targetClean, $results)
    Section "IP RESOLUTION"
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($targetClean) | ForEach-Object { $_.IPAddressToString } | Sort-Object -Unique
        $results.ip = $ips
        foreach ($ip in $ips) {
            Log "  [IP] $targetClean -> $ip" "Green"
        }
    } catch {
        Log "  Could not resolve $targetClean" "Red"
    }
}

# =====================================================================
# 10. SCORE CALCULATION
# =====================================================================
function Update-Score {
    param($results)
    $penalties = 0
    
    # Missing headers
    if ($results.headers_missing) { $penalties += $results.headers_missing.Count * 5 }
    
    # Vulnerabilities
    if ($results.vulns) { $penalties += $results.vulns.Count * 15 }
    
    # No HTTPS redirect
    if ($results.vulns -match "HTTP available") { $penalties += 10 }
    
    # Open ports (non-standard)
    $webPorts = @(80,443,8080,8443)
    if ($results.ports) {
        $penalties += ($results.ports | Where-Object { $_ -notin $webPorts }).Count * 5
    }
    
    $score = [math]::Max(0, 100 - $penalties)
    $results.score = $score
}

# =====================================================================
# 11. HTML REPORT
# =====================================================================
function Generate-Report {
    param($baseUrl, $targetClean, $results)
    Section "REPORT GENERATION"
    $reportFile = "$OutputDir\report_$($targetClean)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $score = if ($results.score -ne $null) { $results.score } else { 0 }
    $grade = if ($score -ge 80) { "A" } elseif ($score -ge 60) { "B" } elseif ($score -ge 40) { "C" } elseif ($score -ge 20) { "D" } else { "E" }
    $scoreClass = if ($score -ge 60) { "good" } elseif ($score -ge 40) { "warn" } else { "bad" }
    
    $headersHtml = "<ul>"
    if ($results.headers_present) { foreach ($h in $results.headers_present) { $headersHtml += "<li class='good'>[OK] $h</li>" } }
    if ($results.headers_missing) { foreach ($h in $results.headers_missing) { $headersHtml += "<li class='bad'>[MISSING] $h</li>" } }
    $headersHtml += "</ul>"
    
    $dirsHtml = ""
    if ($results.dirs) {
        $dirsHtml = "<div class='section'><h2>Discovered Paths</h2><ul>"
        foreach ($d in $results.dirs) { $dirsHtml += "<li class='warn'>[$($d.code)] $($d.path)</li>" }
        $dirsHtml += "</ul></div>"
    }
    
    $subHtml = ""
    if ($results.subdomains -and $results.subdomains.Count -gt 0) {
        $subHtml = "<div class='section'><h2>Subdomains</h2><ul>"
        foreach ($s in $results.subdomains) { $subHtml += "<li class='info'>[SUB] $s</li>" }
        $subHtml += "</ul></div>"
    }
    
    $portHtml = ""
    if ($results.ports -and $results.ports.Count -gt 0) {
        $portHtml = "<div class='section'><h2>Open Ports</h2><ul>"
        foreach ($p in $results.ports) { $portHtml += "<li class='warn'>[PORT] Port $p</li>" }
        $portHtml += "</ul></div>"
    }
    
    $vulnHtml = ""
    if ($results.vulns -and $results.vulns.Count -gt 0) {
        $vulnHtml = "<div class='section'><h2>Vulnerabilities Found</h2><ul>"
        foreach ($v in $results.vulns) { $vulnHtml += "<li class='bad'>[VULN] $v</li>" }
        $vulnHtml += "</ul></div>"
    } else {
        $vulnHtml = "<div class='section'><h2>Vulnerabilities</h2><p class='good'>No vulnerabilities detected in basic scan</p></div>"
    }
    
    $cmsHtml = ""
    if ($results.cms -and $results.cms.Count -gt 0) {
        $cmsHtml = "<div class='section'><h2>CMS Detection</h2><ul>"
        foreach ($c in $results.cms) { $cmsHtml += "<li>$c</li>" }
        $cmsHtml += "</ul></div>"
    }
    
    $emailHtml = ""
    if ($results.emails -and $results.emails.Count -gt 0) {
        $emailHtml = "<div class='section'><h2>Emails Found</h2><ul>"
        foreach ($e in $results.emails) { $emailHtml += "<li>$e</li>" }
        $emailHtml += "</ul></div>"
    }
    
    $linkHtml = ""
    if ($results.links -and $results.links.Count -gt 0) {
        $linkHtml = "<div class='section'><h2>Internal Links</h2><ul>"
        foreach ($l in $results.links) { $linkHtml += "<li><a href='$l' style='color:#8888ff'>$l</a></li>" }
        $linkHtml += "</ul></div>"
    }
    
    $ipHtml = ""
    if ($results.ip) { $ipHtml = "<tr><th>IP Address</th><td>$($results.ip -join ', ')</td></tr>" }
    $techHtml = ""
    if ($results.tech) { $techHtml = "<tr><th>Tech Stack</th><td>$($results.tech -join ', ')</td></tr>" }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report - $targetClean</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',sans-serif; background:#0f0f1a; color:#e0e0e0; padding:20px; }
h1 { color:#00d4ff; border-bottom:2px solid #00d4ff; padding-bottom:10px; }
h2 { color:#ffd700; margin:20px 0 10px; padding:8px; background:#1a1a2e; border-radius:5px; }
.section { background:#1a1a2e; border-radius:8px; padding:15px; margin:10px 0; }
.good { color:#00ff88; } .warn { color:#ffd700; } .bad { color:#ff4444; } .info { color:#8888ff; }
ul { list-style:none; padding:0; }
li { padding:3px 0; border-bottom:1px solid #2a2a3e; }
code { background:#2a2a3e; padding:2px 6px; border-radius:3px; font-size:13px; }
.footer { text-align:center; margin-top:30px; color:#666; font-size:12px; }
table { width:100%; border-collapse:collapse; margin:10px 0; }
th,td { padding:8px; text-align:left; border-bottom:1px solid #2a2a3e; }
th { background:#2a2a3e; color:#ffd700; }
.score-box { display:inline-block; padding:10px 20px; border-radius:5px; font-size:24px; font-weight:bold; margin:10px 0; }
</style>
</head>
<body>
<h1>Recon Report: $targetClean</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

<div class="section">
<h2>Summary</h2>
<table>
<tr><th>Target</th><td>$targetClean</td></tr>
$ipHtml
$techHtml
<tr><th>HTTP Status</th><td>$($results.http_status)</td></tr>
<tr><th>Page Size</th><td>$($results.page_size) bytes</td></tr>
</table>
<div class='score-box $scoreClass'>Security Score: $score/100 ($grade)</div>
</div>

<div class='section'><h2>Security Headers</h2>$headersHtml</div>
$dirsHtml
$subHtml
$portHtml
$vulnHtml
$cmsHtml
$emailHtml
$linkHtml

<div class='footer'>
<p>Generated by Recon Automation Tool v3.0</p>
<p>Web Security Audit</p>
</div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportFile -Encoding UTF8
    Log "  [HTML Report] $reportFile" "Green"
    return $reportFile
}

# =====================================================================
# MAIN
# =====================================================================
Write-Banner

# Validate
if (-not $Target -and -not $TargetFile) {
    Log "Usage: .\recon.ps1 -Target example.com [-Quick|-Full]" "Yellow"
    Log "       .\recon.ps1 -TargetFile list.txt -Quick" "Yellow"
    exit
}

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$targets = @()
if ($TargetFile) {
    if (Test-Path $TargetFile) { $targets = Get-Content $TargetFile | Where-Object { $_ -match "\S" } | ForEach-Object { Get-CleanTarget $_ } }
    else { Log "File not found: $TargetFile" "Red"; exit }
} else {
    $targets = @(Get-CleanTarget $Target)
}

foreach ($t in $targets) {
    $baseUrl = Get-Url $t
    $cleanTarget = Get-CleanTarget $t
    
    Log "`n============================================================" "Cyan"
    Log " Scanning: $t" "Cyan"
    Log " Base URL: $baseUrl" "Cyan"
    Log "============================================================" "Cyan"
    
    $results = @{
        http_status = 0
        page_size = 0
        score = 0
        headers_present = $null
        headers_missing = $null
        tech = $null
        ip = $null
        dirs = $null
        subdomains = $null
        ports = $null
        vulns = $null
        cms = $null
        emails = $null
        links = $null
        internal_links = $null
    }
    
    # Always run these
    Scan-IP $baseUrl $cleanTarget $results
    Scan-SecurityHeaders $baseUrl $cleanTarget $results
    Scan-Directories $baseUrl $cleanTarget $results
    Scan-CMS $baseUrl $cleanTarget $results
    Scan-Emails $baseUrl $cleanTarget $results
    Scan-Links $baseUrl $cleanTarget $results
    Scan-Vulns $baseUrl $cleanTarget $results
    
    # Conditional
    if ($Full) {
        Scan-Ports $baseUrl $cleanTarget $results
        Scan-Subdomains $baseUrl $cleanTarget $results
    }
    
    Update-Score $results
    Generate-Report $baseUrl $cleanTarget $results
    
    Log "`nScan complete for $t" "Green"
}

Log "`nAll scans completed." "Green"