<#
.SYNOPSIS
    Recon Automation Tool v3.5 - Universal Web Security Scanner
.DESCRIPTION
    Multi-module recon scanner with concurrency, big wordlists, WAF detection,
    DNS enumeration, SSL analysis, tech fingerprinting, CVE scanning,
    Wayback machine, API fuzzing, SQLi/XSS/LFI detection, JSON output
.PARAMETER Target
    Target domain or URL to scan
.PARAMETER TargetFile
    File containing list of targets (one per line)
.PARAMETER Quick
    Quick scan (headers, dirs, CMS, basic vulns)
.PARAMETER Full
    Full scan (all modules)
.PARAMETER Json
    Export results as JSON
.PARAMETER OutputDir
    Output directory for reports
.EXAMPLE
    .\recon.ps1 -Target example.com -Quick
    .\recon.ps1 -Target example.com -Full -Json
    .\recon.ps1 -TargetFile targets.txt -Quick
#>

param(
    [string]$Target,
    [string]$TargetFile,
    [switch]$Quick,
    [switch]$Full,
    [switch]$Json,
    [string]$OutputDir = "D:\TUGAS\output\recon"
)

$Script:VERSION = "3.5"

# =====================================================================
# EXPANDED WORDLISTS
# =====================================================================
$Script:wordlist = @(
"admin","login","api","wp-admin","wp-content","backup","config",".env","test","dashboard","uploads","assets",
"static","js","css","images","img","vendor","node_modules","src","app","public","private","temp","logs","error",
"404","500","robots.txt","sitemap.xml","cgi-bin","includes","modules","plugins","themes","core","data","db",
"database","sql","phpmyadmin","administrator","panel","manager","management","console","controlpanel","cpanel",
"webmail","mail","owa","exchange","autodiscover","remote","desktop","rdp","vpn","proxy","socks","gateway","portal",
"intranet","extranet","help","support","chat","contact","about","faq","terms","privacy","license","swagger","docs",
"api-docs","api/v1","api/v2","graphql","soap","rest","api/auth","api/users","api/admin","api/config","api/status",
"api/health","api/metrics","api/logs","api/debug","api/.env","api/swagger","api/docs","api/graphql",
"user","users","member","members","customer","customers","client","clients","order","orders","cart","checkout",
"payment","payments","invoice","invoices","transaction","transactions","subscription","subscriptions",
"account","accounts","profile","profiles","setting","settings","preference","preferences","notification","notifications",
"message","messages","inbox","outbox","draft","drafts","search","browse","category","categories","product","products",
"item","items","service","services","page","pages","post","posts","article","articles","news","blog","gallery",
"video","videos","media","file","files","document","documents","download","downloads","upload","uploads",
"attachment","attachments","asset","assets","resource","resources","component","components","widget","widgets",
"template","templates","layout","layouts","theme","themes","style","styles","script","scripts","font","fonts",
"icon","icons","image","images","img","picture","pictures","photo","photos","graphic","graphics",
"batch","cron","task","tasks","job","jobs","queue","queues","worker","workers","schedule","schedules",
"webhook","webhooks","callback","callbacks","hook","hooks","trigger","triggers",
"event","events","listen","listener","listeners","broadcast","broadcasts","pub","sub","pubsub","mqtt",
"cache","redis","memcache","memcached","session","sessions","token","tokens","oauth","oauth2","openid",
"saml","sso","ldap","kerberos","ntlm","auth","authenticate","authorize","login","logout","signin","signup",
"register","registration","verify","verification","reset","password","forgot","recover","recovery",
"adminer","adminer.php","pgadmin","phppgadmin","mysql","mariadb","mongodb","elasticsearch","kibana",
"grafana","prometheus","alertmanager","consul","vault","nomad","terraform","ansible","puppet","chef",
"docker","kubernetes","k8s","rancher","openshift","istio","envoy","linkerd","traefik","nginx","apache",
"haproxy","squid","tinyproxy","socks5","socks4","ssh","ssh2","telnet","ftp","sftp","ftps","smb","smb2",
"nfs","nfs4","webdav","dav","caldav","carddav","rss","atom","feed","rdf","xml","json","yaml","yml",
"toml","ini","cfg","conf","cnf","reg","registry","install","setup","config","configure","configuration",
".htaccess","htpasswd","htgroup","htdigest","svn",".svn","git",".git","hg",".hg","bzr",".bzr",
"CVS","cvs",".cvs","DS_Store",".DS_Store","_darcs","P4CONFIG","P4IGNORE",
"crossdomain.xml","clientaccesspolicy.xml","security.txt","humans.txt","ads.txt",
"app-ads.txt","keybase.txt","mta-sts.txt","well-known","/.well-known/security.txt",
"actuator","actuator/health","actuator/info","actuator/env","actuator/beans","actuator/mappings",
"actuator/metrics","actuator/configprops","actuator/threaddump","actuator/heapdump","actuator/loggers",
"actuator/logfile","actuator/auditevents","actuator/httptrace","actuator/scheduledtasks",
"swagger-ui.html","swagger-ui/","swagger-resources","swagger.json","swagger.yaml","swagger.yml",
"api/swagger.json","api/swagger.yaml","api/swagger.yml","api/schema","api/schemas",
"openapi.json","openapi.yaml","openapi.yml","api/openapi.json",
"graphql","graphiql","playground","api/graphql","api/graphiql","api/playground",
"console","admin/console","administrator/console","debug","debug/","debug/default/",
"tests","test/","test/index.php","test.php","testing","beta","alpha","staging","stage","dev",
"development","sandbox","demo","vercel","netlify","heroku","aws","azure","gcp","firebase",
"cloud","serverless","lambda","functions","edge","cdn","fastly","cloudfront","cloudflare"
)

$Script:subdomainList = @(
"www","mail","remote","blog","shop","api","dev","test","admin","cdn","static","assets","images","img",
"video","media","download","files","ftp","smtp","pop3","imap","webmail","owa","exchange","vpn","proxy",
"secure","login","portal","app","mobile","m","www2","www3","backup","staging","stage","beta","alpha",
"demo","sandbox","dev2","dev3","test2","monitor","status","help","support","docs","wiki","forum",
"community","chat","board","git","svn","jenkins","jira","confluence","pma","phpmyadmin","sql","db",
"database","config","setup","install","license","api","gateway","services","service",
"ns1","ns2","ns3","ns4","dns1","dns2","mx","mx1","mx2","mail1","mail2","smtp","pop3","imap",
"autodiscover","autoconfig","mta-sts","caldav","carddav","webdav","dav",
"adminer","pgadmin","grafana","kibana","prometheus","alertmanager","consul","vault","nomad",
"docker","kubernetes","k8s","rancher","rancher2","istio","traefik","haproxy","nginx",
"jenkins","jira","confluence","bitbucket","sonar","sonarqube","nexus","artifactory",
"gitlab","gitea","gogs","github","gitlab-ci","jenkins-ci","teamcity","bamboo","buddy",
"argocd","argo","spinnaker","drone","circleci","travis-ci",
"redis","memcache","memcached","mongo","mongodb","mysql","pgsql","postgres","couchdb",
"cassandra","elasticsearch","elastic","kibana","logstash","rabbitmq","activemq","kafka",
"zookeeper","etcd","consul",
"report","reports","analytics","stats","statistics","logs","log","logging",
"docs","doc","documentation","api-docs","apidocs","swagger","swagger-ui",
"graphql","graphiql","playground","hasura","prisma",
"status","uptime","health","monitor","monitoring","ping","heartbeat",
"cdn2","cdn3","static2","media2","img2","assets2",
"mail2","smtp2","pop2","imap2",
"vpn2","proxy2","secure2","remote2",
"dev1","dev3","dev4","dev5",
"test1","test3","test4","test5",
"staging2","staging3",
"prod","production","preprod","pre-prod",
"dr","disaster-recovery","backup2","backup3",
"internal","external","corp","corporate",
"partner","partners","vendor","vendors",
"supplier","suppliers","distributor","distributors",
"reseller","resellers","affiliate","affiliates",
"wholesale","retail","store","shop2",
"career","careers","job","jobs","recruit","recruitment",
"hr","human-resources","payroll","benefits",
"legal","compliance","audit","auditor",
"finance","accounting","tax","taxes",
"billing","invoice","invoices",
"ticket","tickets","support2","helpdesk",
"forum2","community2","user","users",
"profile","profiles","member","members",
"account","accounts","my","myaccount",
"dashboard2","panel2","manager2",
"crm","erp","hris","lms","scorm",
"analytics2","stats2","metrics",
"bug","bugs","issue","issues",
"feedback","suggestion","suggestions",
"roadmap","changelog","release","releases",
"blog2","news","newsletter",
"event","events","webinar","webinars",
"training","learn","academy","education",
"statuspage","status-page","uptime2"
)

$Script:commonPorts = @(21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,8080,8443,9000,9090,10000,11211,27017)

$Script:userAgents = @(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "curl/8.4.0"
)

# =====================================================================
# HELPERS
# =====================================================================
function Write-Banner {
    Clear-Host
    $banner = @"

    RECON AUTOMATION TOOL v$($Script:VERSION)
    Universal Web Security Scanner
    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Features: Concurrent + WAF + DNS + SSL + CMS + Wayback + SQLi/XSS/LFI
    Output: HTML + JSON

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
    param([string]$Url, [int]$TimeoutSec = 15, [string]$Method = "GET")
    try {
        $ua = $Script:userAgents | Get-Random
        $resp = Invoke-WebRequest -Uri $Url -UserAgent $ua -TimeoutSec $TimeoutSec -UseBasicParsing -Method $Method -ErrorAction Stop
        return $resp
    } catch {
        return $null
    }
}

function Invoke-WebRequestQuick {
    param([string]$Url, [int]$TimeoutSec = 8)
    try {
        $ua = $Script:userAgents | Get-Random
        $resp = Invoke-WebRequest -Uri $Url -UserAgent $ua -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        return @{Status = [int]$resp.StatusCode; Headers = $resp.Headers; Raw = $resp}
    } catch {
        return $null
    }
}

# Parallel execution helper (works in PS 5.1 via RunspacePool)
function Invoke-Parallel {
    param([array]$Items, [scriptblock]$ScriptBlock, [int]$Threads = 20, [string]$LogLabel = "", [int]$TimeoutTotal = 120)
    $results = @()
    if ($Items.Count -eq 0) { return $results }
    
    $pool = [RunspaceFactory]::CreateRunspacePool(1, [Math]::Min($Threads, $Items.Count))
    $pool.Open()
    
    $psList = @()
    $handles = @()
    $total = $Items.Count
    
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($ScriptBlock).AddArgument($Items[$i])
        $handle = $ps.BeginInvoke()
        $psList += $ps
        $handles += $handle
        if ($LogLabel) { Write-Progress -Activity $LogLabel -Status "$($i+1)/$total" -PercentComplete (($i+1)/$total*100) }
    }
    
    for ($i = 0; $i -lt $psList.Count; $i++) {
        try {
            $result = $psList[$i].EndInvoke($handles[$i])
            if ($result) { $results += $result }
        } catch {}
        $psList[$i].Dispose()
    }
    
    $pool.Close()
    $pool.Dispose()
    Write-Progress -Activity $LogLabel -Completed
    return $results
}

function Test-Port {
    param([string]$Hostname, [int]$Port, [int]$TimeoutMs = 2000)
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
# 1. IP RESOLUTION
# =====================================================================
function Scan-IP {
    param($baseUrl, $targetClean, $results)
    Section "IP RESOLUTION"
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($targetClean) | ForEach-Object { $_.IPAddressToString } | Sort-Object -Unique
        $results.ip = $ips
        foreach ($ip in $ips) { Log "  [IP] $targetClean -> $ip" "Green" }
    } catch {
        Log "  Could not resolve $targetClean" "Red"
    }
}

# =====================================================================
# 2. SECURITY HEADERS + WAF DETECTION
# =====================================================================
function Scan-SecurityHeaders {
    param($baseUrl, $targetClean, $results)
    Section "SECURITY HEADERS + WAF DETECTION"
    
    $resp = Invoke-WebRequestSafe $baseUrl -TimeoutSec 15 -Method GET
    if (-not $resp) {
        Log "Failed to fetch $baseUrl" "Red"; return
    }
    
    $results.http_status = [int]$resp.StatusCode
    $results.page_size = if ($resp.RawContentStreamHandle) { $resp.RawContentStreamHandle.Length } else { $resp.Content.Length }
    
    # --- Security headers ---
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
    $present = @(); $missing = @()
    foreach ($h in $headersToCheck.Keys) {
        if ($resp.Headers.ContainsKey($h)) { $present += $headersToCheck[$h]; Log "  [OK] $($headersToCheck[$h])" "Green" }
        else { $missing += $headersToCheck[$h]; Log "  [WARN] $($headersToCheck[$h]) missing" "Yellow" }
    }
    $results.headers_present = $present
    $results.headers_missing = $missing
    
    # --- WAF Detection ---
    $waf = @()
    $wafHeaders = @{
        "CF-Cache-Status" = "Cloudflare"
        "CF-Ray" = "Cloudflare"
        "X-Sucuri-ID" = "Sucuri"
        "X-Sucuri-Cache" = "Sucuri"
        "X-Edge-Location" = "StackPath"
        "X-WAF-Event-Info" = "StackPath"
        "X-Akamai-Transformed" = "Akamai"
        "X-Akamai-Request-ID" = "Akamai"
        "X-Nginx-Proxy" = "Nginx WAF"
        "X-Mod-Security" = "ModSecurity"
        "X-Protected-By" = "SiteGround"
        "X-Iinfo" = "Incapsula/Imperva"
        "X-CDN" = "CDN (generic)"
        "Server" = $null  # Check server header separately
    }
    foreach ($h in $wafHeaders.Keys) {
        if ($resp.Headers.ContainsKey($h)) {
            $waf += if ($wafHeaders[$h]) { $wafHeaders[$h] } else { $resp.Headers[$h] }
        }
    }
    # Server header specific WAF checks
    if ($resp.Headers.ContainsKey("Server")) {
        $srv = $resp.Headers["Server"]
        if ($srv -match "cloudflare") { $waf += "Cloudflare" }
        if ($srv -match "akamai") { $waf += "Akamai" }
        if ($srv -match "sucuri") { $waf += "Sucuri" }
        if ($srv -match "aws") { $waf += "AWS" }
    }
    # Cookie check for WAF
    if ($resp.Headers.ContainsKey("Set-Cookie")) {
        $ck = $resp.Headers["Set-Cookie"] -join " "
        if ($ck -match "__cfduid") { $waf += "Cloudflare" }
        if ($ck -match "ak_bmsc") { $waf += "Akamai Blockchain" }
        if ($ck -match "visid_incap") { $waf += "Incapsula" }
        if ($ck -match "nlbi_") { $waf += "Incapsula" }
    }
    $results.waf = @($waf | ForEach-Object { $_.ToLower() } | Select-Object -Unique)
    if ($results.waf.Count -gt 0) {
        foreach ($w in $results.waf) { Log "  [WAF] $w detected" "Yellow" }
    } else {
        Log "  [WAF] No WAF detected" "Green"
    }
    
    # Tech detection from headers
    $tech = @()
    if ($resp.Headers.ContainsKey("Server")) { $tech += "Server:$($resp.Headers['Server'])" }
    if ($resp.Headers.ContainsKey("X-Powered-By")) { $tech += $resp.Headers['X-Powered-By'] }
    if ($resp.Headers.ContainsKey("X-Generator")) { $tech += $resp.Headers['X-Generator'] }
    $results.tech = $tech
    
    $score = [math]::Round(($present.Count / $headersToCheck.Count) * 100, 0)
    $results.score = $score
    Log "Security Score: $score/100" "Green"
}

# =====================================================================
# 3. DIRECTORY SCAN (PARALLEL)
# =====================================================================
function Scan-Directories {
    param($baseUrl, $targetClean, $results)
    Section "DIRECTORY SCAN ($($Script:wordlist.Count) paths, 20x concurrent)"
    
    $found = @()
    $results_dir = Invoke-Parallel -Items $Script:wordlist -Threads 20 -LogLabel "Directory Scan" -ScriptBlock {
        param($path)
        $url = "$using:baseUrl/$path"
        try {
            $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            $r = Invoke-WebRequest -Uri $url -UserAgent $ua -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
            if ([int]$r.StatusCode -ne 404 -and [int]$r.StatusCode -ne 429) {
                return @{path = $url; code = [int]$r.StatusCode}
            }
        } catch {}
        return $null
    }
    $found = $results_dir | Where-Object { $_ }
    $results.dirs = $found
    foreach ($d in $found) {
        $color = if ($d.code -le 400) { "Green" } else { "Yellow" }
        Log "  [FOUND] $($d.path) ($($d.code))" $color
    }
    Log "Found $($found.Count) accessible paths" "Cyan"
}

# =====================================================================
# 4. SUBDOMAIN ENUMERATION (PARALLEL)
# =====================================================================
function Scan-Subdomains {
    param($baseUrl, $targetClean, $results)
    Section "SUBDOMAIN ENUMERATION ($($Script:subdomainList.Count) subs, 30x concurrent)"
    
    $found = Invoke-Parallel -Items $Script:subdomainList -Threads 30 -LogLabel "Subdomain Scan" -ScriptBlock {
        param($sub)
        $url = "https://$sub.$using:targetClean"
        try {
            $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            $r = Invoke-WebRequest -Uri $url -UserAgent $ua -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
            $code = [int]$r.StatusCode
            if ($code -ne 404 -and $code -ne 429 -and $code -ne 0) {
                return @{subdomain = $sub; url = $url; status = $code}
            }
        } catch {
            # Check if DNS resolves even if HTTP fails
            try {
                $null = [System.Net.Dns]::GetHostEntry("$sub.$using:targetClean")
                return @{subdomain = $sub; url = $url; status = "DNS-only"}
            } catch {}
        }
        return $null
    }
    $found = $found | Where-Object { $_ }
    $results.subdomains = $found
    foreach ($f in $found) {
        Log "  [FOUND] $($f.url) ($($f.status))" "Green"
    }
    Log "Found $($found.Count) subdomains" "Cyan"
}

# =====================================================================
# 5. PORT SCAN (PARALLEL, FASTER)
# =====================================================================
function Scan-Ports {
    param($baseUrl, $targetClean, $results)
    Section "PORT SCAN (35 ports, 35x concurrent, 2s timeout)"
    
    $serviceMap = @{21="FTP";22="SSH";23="Telnet";25="SMTP";53="DNS";80="HTTP";110="POP3";111="RPC"
                   135="RPC";139="NetBIOS";143="IMAP";443="HTTPS";445="SMB";993="IMAPS";995="POP3S"
                   1433="MSSQL";1521="Oracle";2049="NFS";3306="MySQL";3389="RDP";5432="PostgreSQL"
                   5900="VNC";5985="WinRM-HTTP";5986="WinRM-HTTPS";6379="Redis";8080="HTTP-Alt"
                   8443="HTTPS-Alt";9000="PHP-FPM";9090="JavaConsole";10000="Webmin";11211="Memcached"
                   27017="MongoDB"}
    
    $openResults = Invoke-Parallel -Items $Script:commonPorts -Threads 35 -LogLabel "Port Scan" -ScriptBlock {
        param($port)
        $h = $using:targetClean
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $async = $tcp.BeginConnect($h, $port, $null, $null)
            $wait = $async.AsyncWaitHandle.WaitOne(2000, $false)
            if ($wait -and $tcp.Connected) {
                $tcp.EndConnect($async) | Out-Null
                $tcp.Close()
                return $port
            }
            $tcp.Close()
        } catch {}
        return $null
    }
    
    $open = @($openResults | Where-Object { $_ } | Sort-Object)
    $results.ports = $open
    foreach ($p in $open) {
        $svc = if ($serviceMap.ContainsKey($p)) { $serviceMap[$p] } else { "Unknown" }
        Log "  [OPEN] Port $p ($svc)" "Red"
    }
    Log "Found $($open.Count) open ports" "Cyan"
}

# =====================================================================
# 6. DNS ENUMERATION
# =====================================================================
function Scan-DNS {
    param($baseUrl, $targetClean, $results)
    Section "DNS ENUMERATION"
    $dnsRecords = @{}
    
    # A / AAAA
    try {
        $a = [System.Net.Dns]::GetHostAddresses($targetClean) | ForEach-Object { $_.IPAddressToString }
        $dnsRecords["A"] = $a
        Log "  [A] $($a -join ', ')" "Green"
    } catch {}
    
    # MX, NS, TXT, CNAME via nslookup
    $recordTypes = @("MX","NS","TXT","CNAME","SOA")
    foreach ($type in $recordTypes) {
        try {
            $r = nslookup -type=$type $targetClean 2>&1
            $lines = $r | Out-String
            if ($lines -match "$type records?:?\s*(.+?)(?:\n|$)") {
                $val = $matches[1] -replace '\s+', ' ' -replace '.* = ', ''
                if ($val -and $val -notmatch 'server|can''t|could not') {
                    $dnsRecords[$type] = @($val.Split(',').Trim() | Where-Object { $_ })
                    foreach ($v in $dnsRecords[$type]) { Log "  [$type] $v" "Green" }
                }
            }
        } catch {}
    }
    
    $results.dns = $dnsRecords
    Log "DNS records found: $($dnsRecords.Count)" "Cyan"
}

# =====================================================================
# 7. SSL/TLS ANALYSIS
# =====================================================================
function Scan-SSL {
    param($baseUrl, $targetClean, $results)
    Section "SSL/TLS ANALYSIS"
    
    if ($baseUrl -notmatch '^https') { Log "  Skipped (HTTP only)" "Yellow"; return }
    
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($targetClean, 443)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { param($s,$c,$ch,$err) $true })
        $ssl.AuthenticateAsClient($targetClean)
        $cert = $ssl.RemoteCertificate
        $subject = $cert.Subject
        $issuer = $cert.Issuer
        $expiry = $cert.GetExpirationDateString()
        $start = $cert.GetEffectiveDateString()
        $algo = $ssl.HashAlgorithm
        $keySize = if ($ssl.KeyExchangeStrength) { $ssl.KeyExchangeStrength } else { 0 }
        
        Log "  Subject: $subject" "Green"
        Log "  Issuer: $issuer" "Green"
        Log "  Valid: $start -> $expiry" "Green"
        Log "  Key Exchange: $algo ($keySize bits)" "Green"
        
        $results.ssl = @{
            subject = $subject
            issuer = $issuer
            valid_from = $start
            valid_to = $expiry
            algorithm = $algo
            key_size = $keySize
        }
        
        # Check expiry
        try {
            $expDate = [DateTime]::Parse($expiry)
            $daysLeft = ($expDate - (Get-Date)).Days
            if ($daysLeft -lt 30) { Log "  [WARN] Certificate expires in $daysLeft days!" "Red" }
            else { Log "  Certificate expires in $daysLeft days" "Green" }
            $results.ssl_days_left = $daysLeft
        } catch {}
        
        $ssl.Close()
        $tcp.Close()
    } catch {
        Log "  SSL analysis failed: $_" "Red"
    }
}

# =====================================================================
# 8. TECH FINGERPRINTING
# =====================================================================
function Scan-TechFingerprint {
    param($baseUrl, $targetClean, $results)
    Section "TECH FINGERPRINTING"
    $techs = @()
    
    $resp = Invoke-WebRequestSafe $baseUrl -TimeoutSec 10
    if (-not $resp) { Log "  No response" "Red"; return }
    
    $content = if ($resp.Content) { $resp.Content } else { "" }
    
    # JavaScript frameworks
    if ($content -match 'react(\.development|\.production)?\.js|__NEXT_DATA__|next\.js|next/static') { $techs += "Next.js" }
    if ($content -match 'vue(\.min)?\.js|__VUE__|createApp|vue-router') { $techs += "Vue.js" }
    if ($content -match 'angular\.(min\.)?js|ng-app|ng-version|angular\.core') { $techs += "Angular" }
    if ($content -match 'jquery(\.min)?\.js|\$\(function|jQuery') { $techs += "jQuery" }
    if ($content -match 'svelte|__SVELTE__') { $techs += "Svelte" }
    if ($content -match 'alpine\.(min\.)?js|x-data') { $techs += "Alpine.js" }
    if ($content -match 'htmx(\.min)?\.js|hx-get|hx-post') { $techs += "HTMX" }
    if ($content -match 'livewire|wire:') { $techs += "Livewire" }
    if ($content -match 'turbo\.(min\.)?js|Turbo\.visit') { $techs += "Turbo/Hotwire" }
    
    # CSS frameworks
    if ($content -match 'tailwindcss|\.tw-|text-\[#|bg-\[#|class="[^"]*flex[^"]*"') { $techs += "Tailwind CSS" }
    if ($content -match 'bootstrap(\.min)?\.css|col-(xs|sm|md|lg)-|glyphicon') { $techs += "Bootstrap" }
    
    # Backend
    if ($resp.Headers.ContainsKey("X-Powered-By")) {
        $powered = $resp.Headers["X-Powered-By"]
        $techs += "Powered-By:$powered"
    }
    if ($content -match 'csrf-token|laravel|livewire') { $techs += "Laravel" }
    if ($content -match 'wp-content|wp-includes|wp-json') { $techs += "WordPress" }
    if ($content -match 'drupal|Drupal\.|drupalSettings') { $techs += "Drupal" }
    if ($content -match 'Joomla|joomla|\.joomla') { $techs += "Joomla" }
    if ($content -match '__INITIAL_STATE__|__NEXT_DATA__|_app\.jsx') { $techs += "React/Next.js" }
    
    # Web server
    if ($resp.Headers.ContainsKey("Server")) { $techs += "Server:$($resp.Headers['Server'])" }
    
    $results.tech_fp = @($techs | Select-Object -Unique)
    foreach ($t in $results.tech_fp) { Log "  [TECH] $t" "Green" }
    if ($results.tech_fp.Count -eq 0) { Log "  No technologies detected" "Yellow" }
}

# =====================================================================
# 9. CMS DETECTION
# =====================================================================
function Scan-CMS {
    param($baseUrl, $targetClean, $results)
    Section "CMS DETECTION"
    $cms = @()
    
    # WordPress
    $wpChecks = @("/wp-content/","/wp-admin/","/wp-includes/","/wp-json/","/xmlrpc.php","/wp-login.php","/wp-signup.php")
    $wpMatch = 0
    foreach ($p in $wpChecks) { $r = Invoke-WebRequestSafe "$baseUrl$p" -TimeoutSec 5; if ($r -and [int]$r.StatusCode -ne 404) { $wpMatch++ } }
    if ($wpMatch -ge 2) { $cms += "WordPress"; Log "  [CMS] WordPress" "Green" }
    
    # Joomla
    $jChecks = @("/components/","/modules/","/templates/","/administrator/","/media/","/includes/","/language/")
    $jMatch = 0
    foreach ($p in $jChecks) { $r = Invoke-WebRequestSafe "$baseUrl$p" -TimeoutSec 5; if ($r -and [int]$r.StatusCode -ne 404) { $jMatch++ } }
    if ($jMatch -ge 2) { $cms += "Joomla"; Log "  [CMS] Joomla" "Green" }
    
    # Drupal
    $dChecks = @("/sites/","/core/","/modules/","/themes/","/node/","/user/","/CHANGELOG.txt")
    $dMatch = 0
    foreach ($p in $dChecks) { $r = Invoke-WebRequestSafe "$baseUrl$p" -TimeoutSec 5; if ($r -and [int]$r.StatusCode -ne 404) { $dMatch++ } }
    if ($dMatch -ge 2) { $cms += "Drupal"; Log "  [CMS] Drupal" "Green" }
    
    # Laravel
    try {
        $r = Invoke-WebRequestSafe "$baseUrl" -TimeoutSec 5
        if ($r -and $r.Content -match 'laravel|csrf-token|livewire|Laravel|__CREATED_BY_LARAVEL__') { $cms += "Laravel"; Log "  [CMS] Laravel" "Green" }
    } catch {}
    
    # Magento
    $mChecks = @("/static/version","/pub/","/media/","/skin/","/index.php/admin")
    $mMatch = 0
    foreach ($p in $mChecks) { $r = Invoke-WebRequestSafe "$baseUrl$p" -TimeoutSec 5; if ($r -and [int]$r.StatusCode -ne 404) { $mMatch++ } }
    if ($mMatch -ge 2) { $cms += "Magento/Adobe Commerce"; Log "  [CMS] Magento" "Green" }
    
    $results.cms = $cms
    if ($cms.Count -eq 0) { Log "  No CMS detected" "Yellow" }
}

# =====================================================================
# 10. VULNERABILITY CHECKS + CVE + SQLi/XSS/LFI
# =====================================================================
function Scan-Vulns {
    param($baseUrl, $targetClean, $results)
    Section "VULNERABILITY CHECKS"
    $vulns = @()
    
    # --- Known sensitive paths ---
    $vulnPaths = @("/.env","/wp-config.php.bak","/config.php.bak","/config.bak","/db.sql","/dump.sql","/backup.sql",
                   "/.git/config","/.svn/entries","/crossdomain.xml","/clientaccesspolicy.xml","/phpinfo.php","/info.php",
                   "/debug","/api/debug","/actuator","/actuator/health","/swagger-ui.html","/api/swagger",
                   "/graphql?query={__schema{types{name}}}","/server-status","/server-info","/phpmyadmin/",
                   "/.aws/credentials","/credentials","/secrets","/secret","/keys","/tokens",
                   "/robots.txt","/sitemap.xml","/security.txt","/Dockerfile","/docker-compose.yml",
                   "/.docker/config.json","/npm-debug.log","/yarn-debug.log","/composer.json","/package.json",
                   "/web.config","/nginx.conf","/.htaccess","/htaccess","/.npmrc","/.env.local",".env.production",
                   "/api/.env","/admin/.env","/config/.env",
                   "/actuator/env","/actuator/beans","/actuator/heapdump","/actuator/threaddump",
                   "/swagger-resources","/v2/api-docs","/v3/api-docs","/openapi.json",
                   "/_debug/","/dev/","/test/","/tests/","/staging/","/beta/")
    
    foreach ($path in $vulnPaths) {
        try {
            $ua = $Script:userAgents | Get-Random
            $r = Invoke-WebRequest "$baseUrl$path" -UserAgent $ua -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            $code = [int]$r.StatusCode
            if ($code -ne 404 -and $code -ne 429 -and $code -ne 403) {
                $vulns += "$path (HTTP $code)"
                Log "  [VULN] $path -> HTTP $code" "Red"
            }
        } catch {}
    }
    
    # --- HTTP check ---
    $httpUrl = $baseUrl -replace '^https://', 'http://'
    if ($httpUrl -ne $baseUrl) {
        try {
            $r = Invoke-WebRequest $httpUrl -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ([int]$r.StatusCode -lt 400) {
                $vulns += "HTTP available (no forced HTTPS redirect)"
                Log "  [VULN] HTTP available (no forced redirect)" "Red"
            }
        } catch {}
    }
    
    # --- CVE patterns ---
    # Check for Spring Boot actuator without auth
    $actCheck = @("/actuator","/actuator/env","/actuator/heapdump")
    foreach ($p in $actCheck) {
        try {
            $r = Invoke-WebRequest "$baseUrl$p" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ([int]$r.StatusCode -eq 200 -and $r.Content -match 'spring|springframework') {
                $vulns += "Spring Boot Actuator exposed (CVE-2023-xxxx) - sensitive endpoints"
                Log "  [VULN] Spring Boot actuator exposed! (CVE potential)" "Red"
                break
            }
        } catch {}
    }
    
    # Check for exposed .git
    try {
        $r = Invoke-WebRequest "$baseUrl/.git/HEAD" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        if ([int]$r.StatusCode -eq 200 -and $r.Content -match 'ref:') {
            $vulns += "Git repository exposed (.git/HEAD)"
            Log "  [VULN] .git repository exposed! (CVE-2023-xxxx)" "Red"
        }
    } catch {}
    
    # --- Basic SQLi detection ---
    $sqliPayloads = @([string][char]39, [string][char]34, "1' OR 1=1", "1"" OR ""1""=""1", "' OR 1=1--", "admin'--")
    foreach ($p in $sqliPayloads) {
        try {
            $url = "$baseUrl/api?q=$([System.Web.HttpUtility]::UrlEncode($p))"
            $r = Invoke-WebRequest $url -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ($r.Content -match 'sql|syntax|mysql|oracle|postgres|odbc|db2|sqlite|driver|unclosed|quoted') {
                $vulns += "Potential SQLi in /api?q= (error-based)"
                Log "  [VULN] Potential SQLi detected!" "Red"
                break
            }
        } catch {}
    }
    
    # --- Basic XSS detection ---
    try {
        $url = "$baseUrl?q=%3Cscript%3Ealert(1)%3C/script%3E"
        $r = Invoke-WebRequest $url -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        if ($r.Content -match '<script>alert\(1\)</script>') {
            $vulns += "Potential XSS (reflected)"
            Log "  [VULN] Potential XSS detected!" "Red"
        }
    } catch {}
    
    # --- Basic LFI detection ---
    $lfiPaths = @("/index.php?page=../../../etc/passwd", "/page=../../../etc/passwd",
                  "/api?file=../../../etc/passwd", "/download?file=../../../etc/passwd")
    foreach ($p in $lfiPaths) {
        try {
            $r = Invoke-WebRequest "$baseUrl$p" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ($r.Content -match 'root:|bin:/') {
                $vulns += "Potential LFI: $p"
                Log "  [VULN] Potential LFI detected!" "Red"
                break
            }
        } catch {}
    }
    
    $results.vulns = @($vulns | Select-Object -Unique)
    $color = if ($results.vulns.Count -gt 0) { "Red" } else { "Green" }
    Log "Found $($results.vulns.Count) potential vulnerabilities" $color
}

# =====================================================================
# 11. WAYBACK MACHINE
# =====================================================================
function Scan-Wayback {
    param($baseUrl, $targetClean, $results)
    Section "WAYBACK MACHINE (archive.org)"
    $wayback = @()
    
    $url = "http://web.archive.org/cdx/search/cdx?url=*.$targetClean/*" + "&output=json&limit=100&fl=original,timestamp,statuscode"
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "Mozilla/5.0")
        $data = $wc.DownloadString($url)
        $json = $data | ConvertFrom-Json
        if ($json.Count -gt 1) {
            for ($i = 1; $i -lt [Math]::Min($json.Count, 20); $i++) {
                $entry = $json[$i]
                $wayback += @{url = $entry[0]; date = $entry[1]; status = $entry[2]}
                Log "  [WAYBACK] $($entry[1]) $($entry[2]) $($entry[0])" "Green"
            }
            Log "Total archived snapshots: $($json.Count - 1)" "Cyan"
        } else {
            Log "  No archived URLs found" "Yellow"
        }
    } catch {
        Log "  Wayback machine check failed: $_" "Yellow"
    }
    
    $results.wayback = $wayback
}

# =====================================================================
# 12. API FUZZING
# =====================================================================
function Scan-APIFuzz {
    param($baseUrl, $targetClean, $results)
    Section "API FUZZING"
    $apiFinds = @()
    
    # Common API parameter names
    $params = @("id","user_id","admin_id","token","api_key","secret","password","passwd","key","file","path",
                "redirect","url","page","next","prev","callback","jsonp","debug","test","env","config",
                "cmd","command","exec","run","action","method","function","func","do","process",
                "order","sort","limit","offset","page","start","end","filter","search","q","query",
                "email","phone","name","username","role","type","status","lang","locale","format")
    
    # GraphQL introspection
    $gqlUrl = "$baseUrl/graphql"
    $gqlBody = '{"query":"{__schema{types{name fields{name}}}}"}'
    try {
        $r = Invoke-WebRequest $gqlUrl -Method POST -Body $gqlBody -ContentType "application/json" -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
        if ($r.Content -match '__schema') {
            $apiFinds += "GraphQL endpoint allows introspection!"
            Log "  [API] GraphQL introspection enabled!" "Red"
        }
    } catch {}
    
    # GraphQL alternative paths
    foreach ($p in @("/graphql","/graphiql","/api/graphql","/query","/api/query","/v1/graphql","/v2/graphql")) {
        try {
            $r = Invoke-WebRequest "$baseUrl$p" -Method POST -Body '{"query":"{__typename}"}' -ContentType "application/json" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ($r.Content -match '__typename' -or [int]$r.StatusCode -eq 200) {
                $apiFinds += "GraphQL endpoint at $p"
                Log "  [API] GraphQL endpoint: $p" "Yellow"
                break
            }
        } catch {}
    }
    
    # Check for common API docs
    foreach ($p in @("/api/docs","/api/swagger","/swagger-ui.html","/api/v1/docs","/api/v2/docs","/docs/api")) {
        try {
            $r = Invoke-WebRequest "$baseUrl$p" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ([int]$r.StatusCode -eq 200) {
                $apiFinds += "API docs at $p"
                Log "  [API] API documentation: $p" "Yellow"
            }
        } catch {}
    }
    
    # Parameter fuzzing on common endpoints
    $endpoints = @("/api/users","/api/admin","/api/config","/api/settings","/api/status")
    foreach ($ep in $endpoints) {
        try {
            $r = Invoke-WebRequest "$baseUrl$ep" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ([int]$r.StatusCode -eq 200 -and $r.Content -match '\[|{|"') {
                $apiFinds += "$ep returns data (no auth required?)"
                Log "  [API] $ep accessible without auth" "Red"
            }
        } catch {}
    }
    
    $results.api_fuzz = @($apiFinds | Select-Object -Unique)
    if ($results.api_fuzz.Count -eq 0) { Log "  No API issues found" "Green" }
}

# =====================================================================
# 13. EMAIL EXTRACTION
# =====================================================================
function Scan-Emails {
    param($baseUrl, $targetClean, $results)
    Section "EMAIL EXTRACTION"
    $emails = @()
    $emailRegex = [regex]'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    $pagesToCheck = @("$baseUrl","$baseUrl/contact","$baseUrl/about","$baseUrl/team","$baseUrl/people","$baseUrl/staff","$baseUrl/directory")
    
    foreach ($page in $pagesToCheck) {
        $resp = Invoke-WebRequestSafe $page
        if ($resp -and $resp.Content) {
            $found = $emailRegex.Matches($resp.Content) | ForEach-Object { $_.Value.ToLower() } | Where-Object { $_ -notmatch '\.png|\.jpg|\.css|example\.com|\.local|\.test|@example' } | Sort-Object -Unique
            foreach ($e in $found) {
                if ($e -notin $emails) { Log "  [EMAIL] $e" "Green"; $emails += $e }
            }
        }
    }
    $results.emails = $emails
    Log "Found $($emails.Count) email addresses" "Cyan"
}

# =====================================================================
# 14. LINK EXTRACTION
# =====================================================================
function Scan-Links {
    param($baseUrl, $targetClean, $results)
    Section "LINK EXTRACTION"
    $links = @(); $internal = @()
    $resp = Invoke-WebRequestSafe $baseUrl
    if ($resp -and $resp.Content) {
        $linkRegex = [regex]'href="([^"]+)"'
        $matches = $linkRegex.Matches($resp.Content)
        foreach ($m in $matches) {
            $url = $m.Groups[1].Value
            if ($url -match '^https?://') {
                $links += $url
                if ($url -match $targetClean) { $internal += $url }
            } elseif ($url -match '^/') { $internal += "$baseUrl$url" }
            elseif ($url -match '^\.\./') { $internal += "$baseUrl$url" }
        }
    }
    $results.links = $links
    $results.internal_links = @($internal | Select-Object -Unique)
    Log "Found $($links.Count) total links, $($internal.Count) internal" "Cyan"
}

# =====================================================================
# 15. SCORE CALCULATION
# =====================================================================
function Update-Score {
    param($results)
    $penalties = 0
    if ($results.headers_missing) { $penalties += $results.headers_missing.Count * 5 }
    if ($results.vulns) { $penalties += $results.vulns.Count * 12 }
    if ($results.vulns -match "HTTP available") { $penalties += 10 }
    if ($results.ssl_days_left -and $results.ssl_days_left -lt 30) { $penalties += 15 }
    $webPorts = @(80,443,8080,8443)
    if ($results.ports) { $penalties += ($results.ports | Where-Object { $_ -notin $webPorts }).Count * 3 }
    if ($results.api_fuzz) { $penalties += $results.api_fuzz.Count * 8 }
    
    $score = [math]::Max(0, 100 - $penalties)
    $results.score = $score
}

# =====================================================================
# 16. JSON EXPORT
# =====================================================================
function Export-JsonResults {
    param($baseUrl, $targetClean, $results)
    $jsonFile = "$OutputDir\report_$($targetClean)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    $export = @{
        tool = "Recon v$Script:VERSION"
        target = $targetClean
        url = $baseUrl
        timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        score = $results.score
        grade = if ($results.score -ge 80) { "A" } elseif ($results.score -ge 60) { "B" } elseif ($results.score -ge 40) { "C" } elseif ($results.score -ge 20) { "D" } else { "E" }
        ip = $results.ip
        http_status = $results.http_status
        page_size = $results.page_size
        tech = $results.tech
        headers_present = $results.headers_present
        headers_missing = $results.headers_missing
        waf = $results.waf
        tech_fp = $results.tech_fp
        cms = $results.cms
        dirs = $results.dirs
        subdomains = $results.subdomains
        ports = $results.ports
        dns = $results.dns
        ssl = $results.ssl
        ssl_days_left = $results.ssl_days_left
        vulns = $results.vulns
        emails = $results.emails
        links = @{total = ($results.links | Measure-Object).Count; internal = ($results.internal_links | Measure-Object).Count}
        api_fuzz = $results.api_fuzz
        wayback = $results.wayback
    }
    
    $export | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
    Log "  [JSON] $jsonFile" "Green"
    return $jsonFile
}

# =====================================================================
# 17. HTML REPORT
# =====================================================================
function Generate-Report {
    param($baseUrl, $targetClean, $results)
    Section "REPORT GENERATION"
    $reportFile = "$OutputDir\report_$($targetClean)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $score = if ($results.score -ne $null) { $results.score } else { 0 }
    $grade = if ($score -ge 80) { "A" } elseif ($score -ge 60) { "B" } elseif ($score -ge 40) { "C" } elseif ($score -ge 20) { "D" } else { "E" }
    $scoreClass = if ($score -ge 60) { "good" } elseif ($score -ge 40) { "warn" } else { "bad" }
    
    # Build sections
    $headersHtml = "<ul>"
    if ($results.headers_present) { foreach ($h in $results.headers_present) { $headersHtml += "<li class='good'>[OK] $h</li>" } }
    if ($results.headers_missing) { foreach ($h in $results.headers_missing) { $headersHtml += "<li class='bad'>[MISSING] $h</li>" } }
    $headersHtml += "</ul>"
    
    $wafHtml = ""
    if ($results.waf -and $results.waf.Count -gt 0) { $wafHtml = "<div class='section'><h2>WAF Detection</h2><ul>"; foreach ($w in $results.waf) { $wafHtml += "<li class='info'>$w</li>" }; $wafHtml += "</ul></div>" }
    
    $techHtml = ""
    if ($results.tech_fp -and $results.tech_fp.Count -gt 0) { $techHtml = "<div class='section'><h2>Technology Stack</h2><ul>"; foreach ($t in $results.tech_fp) { $techHtml += "<li>$t</li>" }; $techHtml += "</ul></div>" }
    
    $cmsHtml = ""
    if ($results.cms -and $results.cms.Count -gt 0) { $cmsHtml = "<div class='section'><h2>CMS Detection</h2><ul>"; foreach ($c in $results.cms) { $cmsHtml += "<li>$c</li>" }; $cmsHtml += "</ul></div>" }
    
    $dnsHtml = ""
    if ($results.dns -and @($results.dns.Keys).Count -gt 0) { $dnsHtml = "<div class='section'><h2>DNS Records</h2><ul>"; foreach ($k in $results.dns.Keys) { foreach ($v in $results.dns[$k]) { $dnsHtml += "<li><b>$k</b>: $v</li>" } }; $dnsHtml += "</ul></div>" }
    
    $sslHtml = ""
    if ($results.ssl) { $sslHtml = "<div class='section'><h2>SSL/TLS</h2><ul><li>Subject: $($results.ssl.subject)</li><li>Issuer: $($results.ssl.issuer)</li><li>Valid: $($results.ssl.valid_from) -> $($results.ssl.valid_to)</li><li>Key: $($results.ssl.algorithm) ($($results.ssl.key_size) bits)</li><li>Expires in: $($results.ssl_days_left) days</li></ul></div>" }
    
    $dirsHtml = ""; if ($results.dirs) { $dirsHtml = "<div class='section'><h2>Discovered Paths ($($results.dirs.Count))</h2><ul>"; foreach ($d in $results.dirs) { $dirsHtml += "<li class='warn'>[$($d.code)] $($d.path)</li>" }; $dirsHtml += "</ul></div>" }
    
    $subHtml = ""; if ($results.subdomains -and $results.subdomains.Count -gt 0) { $subHtml = "<div class='section'><h2>Subdomains ($($results.subdomains.Count))</h2><ul>"; foreach ($s in $results.subdomains) { $subHtml += "<li class='info'>$($s.url) ($($s.status))</li>" }; $subHtml += "</ul></div>" }
    
    $portHtml = ""; if ($results.ports -and $results.ports.Count -gt 0) { $portHtml = "<div class='section'><h2>Open Ports ($($results.ports.Count))</h2><ul>"; foreach ($p in $results.ports) { $portHtml += "<li class='warn'>Port $p</li>" }; $portHtml += "</ul></div>" }
    
    $vulnHtml = ""; if ($results.vulns -and $results.vulns.Count -gt 0) { $vulnHtml = "<div class='section'><h2>Vulnerabilities Found ($($results.vulns.Count))</h2><ul>"; foreach ($v in $results.vulns) { $vulnHtml += "<li class='bad'>$v</li>" }; $vulnHtml += "</ul></div>" } else { $vulnHtml = "<div class='section'><h2>Vulnerabilities</h2><p class='good'>No vulnerabilities detected in basic scan</p></div>" }
    
    $emailHtml = ""; if ($results.emails -and $results.emails.Count -gt 0) { $emailHtml = "<div class='section'><h2>Emails Found</h2><ul>"; foreach ($e in $results.emails) { $emailHtml += "<li>$e</li>" }; $emailHtml += "</ul></div>" }
    
    $linkHtml = ""; if ($results.internal_links -and $results.internal_links.Count -gt 0) { $linkHtml = "<div class='section'><h2>Internal Links</h2><ul>"; foreach ($l in $results.internal_links) { $linkHtml += "<li><a href='$l' style='color:#8888ff'>$l</a></li>" }; $linkHtml += "</ul></div>" }
    
    $apiHtml = ""; if ($results.api_fuzz -and $results.api_fuzz.Count -gt 0) { $apiHtml = "<div class='section'><h2>API / GraphQL</h2><ul>"; foreach ($a in $results.api_fuzz) { $apiHtml += "<li class='warn'>$a</li>" }; $apiHtml += "</ul></div>" }
    
    $waybackHtml = ""; if ($results.wayback -and $results.wayback.Count -gt 0) { $waybackHtml = "<div class='section'><h2>Wayback Machine (last 20)</h2><ul>"; foreach ($w in $results.wayback) { $waybackHtml += "<li>$($w.date) [$($w.status)] <a href='$($w.url)' style='color:#8888ff'>$($w.url)</a></li>" }; $waybackHtml += "</ul></div>" }
    
    $ipHtml = ""; if ($results.ip) { $ipHtml = "<tr><th>IP Address</th><td>$($results.ip -join ', ')</td></tr>" }
    $techRowHtml = ""; if ($results.tech) { $techRowHtml = "<tr><th>Tech (Headers)</th><td>$($results.tech -join ', ')</td></tr>" }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report - $targetClean</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',sans-serif; background:#0f0f1a; color:#e0e0e0; padding:20px; }
h1 { color:#00d4ff; border-bottom:2px solid #00d4ff; padding-bottom:10px; font-size:28px; }
h2 { color:#ffd700; margin:20px 0 10px; padding:8px; background:#1a1a2e; border-radius:5px; font-size:18px; }
.section { background:#1a1a2e; border-radius:8px; padding:15px; margin:10px 0; }
.good { color:#00ff88; } .warn { color:#ffd700; } .bad { color:#ff4444; } .info { color:#8888ff; }
ul { list-style:none; padding:0; }
li { padding:4px 0; border-bottom:1px solid #2a2a3e; font-size:13px; }
.footer { text-align:center; margin-top:30px; color:#666; font-size:12px; }
table { width:100%; border-collapse:collapse; margin:10px 0; }
th,td { padding:8px; text-align:left; border-bottom:1px solid #2a2a3e; }
th { background:#2a2a3e; color:#ffd700; }
.score-box { display:inline-block; padding:10px 20px; border-radius:5px; font-size:24px; font-weight:bold; margin:10px 0; }
.summary-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
.meta { color:#888; font-size:12px; }
</style>
</head>
<body>
<h1>Recon Report v$Script:VERSION: $targetClean</h1>
<p class='meta'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

<div class="section">
<h2>Summary</h2>
<table>
<tr><th>Target</th><td>$targetClean</td></tr>
$ipHtml
$techRowHtml
<tr><th>HTTP Status</th><td>$($results.http_status)</td></tr>
<tr><th>Page Size</th><td>$($results.page_size) bytes</td></tr>
</table>
<div class='score-box $scoreClass'>Security Score: $score/100 ($grade)</div>
</div>

<div class='section'><h2>Security Headers</h2>$headersHtml</div>
$wafHtml
$techHtml
$cmsHtml
$dnsHtml
$sslHtml
$dirsHtml
$subHtml
$portHtml
$vulnHtml
$apiHtml
$emailHtml
$linkHtml
$waybackHtml

<div class='footer'>
<p>Generated by Recon Automation Tool v$Script:VERSION</p>
<p>Web Security Audit</p>
</div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportFile -Encoding UTF8
    Log "  [HTML] $reportFile" "Green"
    return $reportFile
}

# =====================================================================
# MAIN
# =====================================================================
Write-Banner

if (-not $Target -and -not $TargetFile) {
    Log "Usage: .\recon.ps1 -Target example.com [-Quick|-Full] [-Json]" "Yellow"
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
    
    $results = @{http_status=0; page_size=0; score=0; headers_present=$null; headers_missing=$null; tech=$null;
                 waf=$null; tech_fp=$null; ip=$null; dirs=$null; subdomains=$null; ports=$null; dns=$null;
                 ssl=$null; ssl_days_left=$null; vulns=$null; cms=$null; emails=$null; links=$null;
                 internal_links=$null; api_fuzz=$null; wayback=$null}
    
    Scan-IP $baseUrl $cleanTarget $results
    Scan-SecurityHeaders $baseUrl $cleanTarget $results
    Scan-Directories $baseUrl $cleanTarget $results
    Scan-CMS $baseUrl $cleanTarget $results
    Scan-Emails $baseUrl $cleanTarget $results
    Scan-Links $baseUrl $cleanTarget $results
    Scan-Vulns $baseUrl $cleanTarget $results
    Scan-TechFingerprint $baseUrl $cleanTarget $results
    Scan-DNS $baseUrl $cleanTarget $results
    Scan-SSL $baseUrl $cleanTarget $results
    Scan-Wayback $baseUrl $cleanTarget $results
    Scan-APIFuzz $baseUrl $cleanTarget $results
    
    if ($Full) {
        Scan-Ports $baseUrl $cleanTarget $results
        Scan-Subdomains $baseUrl $cleanTarget $results
    }
    
    Update-Score $results
    Generate-Report $baseUrl $cleanTarget $results
    if ($Json) { Export-JsonResults $baseUrl $cleanTarget $results }
    
    Log "`nScan complete for $t" "Green"
}

Log "`nAll scans completed." "Green"