<# 
.SYNOPSIS
  End-to-end root-cause triage for ERR_CONNECTION_RESET on Windows.

.DESCRIPTION
  Runs sequential diagnostics:
   1) Baseline & environment
   2) Internet reachability (ICMP/TCP), DNS resolution
   3) DNS cache flush + validation
   4) Proxy discovery (WinINET & WinHTTP) and effective settings
   5) Wi‑Fi profile sanity & current link health
   6) MTU/fragmentation test (binary search)
   7) HOSTS file anomaly scan
   8) Time/TLS sanity (NTP skew)
   9) Windows Firewall quick check (common blocks)
  10) Browser-risk indicators (Chrome policies & extensions snapshot)
  11) Kick off Microsoft Defender Quick Scan (as Chrome Cleanup Tool replacement)
  12) Consolidated findings + remediation hints

  Writes a detailed log on Desktop and prints a final “YOUSTABLE HOSTING” banner.

.NOTES
  Author: YouStable – Windows OS Triage
  Requires: PowerShell 5+, Admin for full coverage
#>

# region --- Elevation check ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
  Write-Host "Re-launching elevated PowerShell..." -ForegroundColor Yellow
  Start-Process powershell -Verb runAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
  exit
}
# endregion

# region --- Setup & helpers ---
$ts     = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = Join-Path ([Environment]::GetFolderPath('Desktop')) "ERR_CONNECTION_RESET_Reports"
$null   = New-Item -ItemType Directory -Force -Path $LogDir
$Log    = Join-Path $LogDir "triage_$ts.log"

function Log([string]$msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format "u"), $msg
  Write-Host $line
  Add-Content -Path $Log -Value $line
}
function Section($title) {
  $bar = ('=' * 80)
  Log $bar
  Log ("{0}" -f $title)
  Log $bar
}
function Try-Command {
  param([scriptblock]$Script,[string]$WhenFails)
  try { & $Script } catch { Log "WARN: $WhenFails : $($_.Exception.Message)" }
}

Section "YouStable ERR_CONNECTION_RESET Diagnostics"
Log "Report path: $Log"

# Capture environment snapshot
Section "1) Baseline & Environment"
Log "Hostname: $(hostname)"
Log "User: $env:USERNAME"
Log "OS: $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).Version)"
Log "PowerShell: $($PSVersionTable.PSVersion.ToString())"
Log "Adapters:"
Get-NetAdapter | Sort-Object ifIndex | Format-Table ifIndex,Name,InterfaceDescription,Status,LinkSpeed -Auto | Out-String | Tee-Object -FilePath $Log -Append | Out-Null
ipconfig /all | Out-String | Tee-Object -FilePath $Log -Append | Out-Null

# region --- 2) Internet reachability & DNS resolution ---
Section "2) Internet Reachability & DNS Resolution"
$targetsICMP = @('1.1.1.1','8.8.8.8')
$targetsTCP  = @(@{Host='dns.google';Port=443}, @{Host='www.microsoft.com';Port=443}, @{Host='www.youtube.com';Port=443})

foreach ($ip in $targetsICMP) {
  $ping = Test-Connection -Count 3 -Quiet -ErrorAction SilentlyContinue -ComputerName $ip
  Log ("ICMP {0}: {1}" -f $ip, ($(if($ping){'OK'} else {'FAIL'})))
}

foreach ($t in $targetsTCP) {
  $tnc = Test-NetConnection -ComputerName $t.Host -Port $t.Port -WarningAction SilentlyContinue
  Log ("TCP {0}:{1} Reachable={2} RTT={3}ms" -f $t.Host,$t.Port,$tnc.TcpTestSucceeded,$tnc.PingReplyDetails.RoundtripTime)
}

$dnsTest = @('microsoft.com','google.com','cloudflare.com')
foreach ($n in $dnsTest) {
  try {
    $r = Resolve-DnsName $n -ErrorAction Stop
    Log ("DNS {0}: OK -> {1}" -f $n, ($r | Where-Object {$_.Type -eq 'A'} | Select-Object -First 1 -ExpandProperty IPAddress))
  } catch {
    Log ("DNS {0}: FAIL -> {1}" -f $n, $_.Exception.Message)
  }
}
# endregion

# region --- 3) Flush DNS cache (safe) & re-validate ---
Section "3) Flushing DNS Cache & Re-Validation"
Try-Command { ipconfig /flushdns | Out-Null } "ipconfig /flushdns failed"
foreach ($n in $dnsTest) {
  try {
    $r = Resolve-DnsName $n -ErrorAction Stop
    Log ("Post-Flush DNS {0}: OK -> {1}" -f $n, ($r | Where-Object {$_.Type -eq 'A'} | Select-Object -First 1 -ExpandProperty IPAddress))
  } catch {
    Log ("Post-Flush DNS {0}: FAIL -> {1}" -f $n, $_.Exception.Message)
  }
}
# endregion

# region --- 4) Proxy discovery (WinINET + WinHTTP) ---
Section "4) Proxy Discovery"
# WinINET (legacy/Chrome/Edge often honor this)
$inetKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$proxyEnabled = (Get-ItemProperty -Path $inetKey -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
$proxyServer  = (Get-ItemProperty -Path $inetKey -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
$autoConfig   = (Get-ItemProperty -Path $inetKey -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL
$autodetect   = (Get-ItemProperty -Path $inetKey -Name AutoDetect -ErrorAction SilentlyContinue).AutoDetect
Log "WinINET: ProxyEnable=$proxyEnabled; ProxyServer=$proxyServer; AutoConfigURL=$autoConfig; AutoDetect=$autodetect"

# WinHTTP (system services stack)
$winhttp = (netsh winhttp show proxy) -join "`n"
Log "WinHTTP:"
$winhttp | Tee-Object -FilePath $Log -Append | Out-Null
# endregion

# region --- 5) Wi‑Fi profile & link health ---
Section "5) Wi‑Fi Profiles & Link Health"
Try-Command { netsh wlan show interfaces | Tee-Object -FilePath $Log -Append | Out-Null } "Failed to query WLAN interfaces"
Try-Command { netsh wlan show profiles   | Tee-Object -FilePath $Log -Append | Out-Null } "Failed to list WLAN profiles"
Try-Command { 
  $wlan = netsh wlan show interfaces
  $ssid = ($wlan | Select-String -Pattern 'SSID\s+:\s+(.*)$' -AllMatches | Select-Object -First 1).Matches.Value -replace 'SSID\s+:\s+',''
  if ($ssid) { Log "Current SSID: $ssid" } else { Log "Current SSID: (not on Wi‑Fi or SSID not found)" }
} "WLAN parsing failed"
# endregion

# region --- 6) MTU / fragmentation sanity (binary search against 8.8.8.8) ---
Section "6) MTU / Fragmentation Test"
function Test-MTU {
  param([string]$Host = '8.8.8.8')
  $low=500; $high=1472; # payload without IP/ICMP headers; 1472+28=1500
  $best=0
  while ($low -le $high) {
    $mid = [int](($low+$high)/2)
    $ok = $false
    try {
      $res = ping $Host -f -l $mid -n 1 2>&1
      if ($LASTEXITCODE -eq 0) { $ok=$true }
    } catch { $ok=$false }
    if ($ok) { $best=$mid; $low=$mid+1 } else { $high=$mid-1 }
  }
  return $best
}
$bestPayload = Test-MTU
if ($bestPayload -gt 0) {
  $recommendedMTU = $bestPayload + 28
  Log "Largest non‑fragmenting payload: $bestPayload bytes -> Recommended MTU ≈ $recommendedMTU"
  if ($recommendedMTU -lt 1500) {
    Log "Possible MTU mismatch on path. Consider setting interface MTU to $recommendedMTU (or next lower standard) to mitigate resets on TLS."
  } else {
    Log "MTU appears normal (≈1500)."
  }
} else {
  Log "MTU test inconclusive."
}
# endregion

# region --- 7) HOSTS anomalies ---
Section "7) HOSTS File Anomaly Scan"
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
  $hosts = Get-Content $hostsPath -ErrorAction SilentlyContinue
  $nonComments = $hosts | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
  Log "HOSTS entries (non-comment) count: $($nonComments.Count)"
  $suspect = $nonComments | Where-Object { $_ -match 'google|facebook|youtube|microsoft|windows|update|cloudflare' }
  if ($suspect) {
    Log "SUSPECT host mappings:"
    $suspect | ForEach-Object { Log "  $_" }
  } else {
    Log "No obvious suspect mappings found."
  }
} else {
  Log "HOSTS file not found (unexpected)."
}
# endregion

# region --- 8) Time/TLS sanity ---
Section "8) Time & TLS Sanity"
$sysTime   = Get-Date
try {
  $netTime = (w32tm /stripchart /computer:time.windows.com /dataonly /samples:3 2>$null) | Select-String -Pattern 'Offset:\s+([-\+]?\d+\.\d+)s' | Select-Object -Last 1
  if ($netTime) {
    $offsetSec = [double]($netTime.Matches.Groups[1].Value)
    Log ("NTP offset vs time.windows.com ≈ {0:N3}s" -f $offsetSec)
    if ([math]::Abs($offsetSec) -gt 60) {
      Log "Clock skew > 60s can break TLS handshakes and cause resets. Sync time (w32tm /resync)."
    }
  } else {
    Log "NTP offset check inconclusive."
  }
} catch { Log "Time check failed: $($_.Exception.Message)" }
# endregion

# region --- 9) Firewall quick probe ---
Section "9) Windows Firewall Quick Probe"
Try-Command { Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction -Auto | Out-String | Tee-Object -FilePath $Log -Append | Out-Null } "Firewall profile query failed"
$httpsProbe = Test-NetConnection -ComputerName "www.google.com" -Port 443 -WarningAction SilentlyContinue
Log ("HTTPS to www.google.com: Reachable={0}, Detailed={1}" -f $httpsProbe.TcpTestSucceeded,$httpsProbe.RemoteAddress)

# endregion

# region --- 10) Chrome indicators (policies & extensions snapshot) ---
Section "10) Chrome Indicators (Policies/Extensions Snapshot)"
# Chrome Cleanup Tool is deprecated by Google; we provide visibility instead.
Log "NOTE: Google Chrome Cleanup Tool has been discontinued by Google. Using supported checks."

# 10a. Chrome policies snapshot (machine scope)
$chromePolicyKey = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (Test-Path $chromePolicyKey) {
  Log "Machine Chrome Policies:"
  Get-ItemProperty -Path $chromePolicyKey | Out-String | Tee-Object -FilePath $Log -Append | Out-Null
} else {
  Log "No machine Chrome policies detected."
}

# 10b. Chrome extensions listing (best‑effort; per user profile Default)
$chromeDir = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\Default\Extensions"
if (Test-Path $chromeDir) {
  $exts = Get-ChildItem $chromeDir -Directory -ErrorAction SilentlyContinue
  if ($exts) {
    Log "Installed Chrome extension IDs (Default profile):"
    foreach ($e in $exts) { Log "  ID: $($e.Name)" }
    Log "If issues correlate with extensions, test Chrome with '--disable-extensions' or in Incognito."
  } else {
    Log "No extensions found under Default profile."
  }
} else {
  Log "Chrome Default profile not found (different profile or Chrome not installed)."
}
# endregion

# region --- 11) Defender Quick Scan (supported alternative to Chrome Cleanup) ---
Section "11) Microsoft Defender Quick Scan"
Try-Command { Start-MpScan -ScanType QuickScan } "Defender scan kickoff failed (Is Defender disabled by another AV?)"
# endregion

# region --- 12) Consolidated Findings & Hints ---
Section "12) Consolidated Findings (Heuristics)"
# Simple heuristics from earlier probes
$icOk  = $targetsTCP | ForEach-Object {
  (Test-NetConnection -ComputerName $_.Host -Port $_.Port -WarningAction SilentlyContinue).TcpTestSucceeded
} | Where-Object { $_ -eq $true }

$dnsOk = $true
foreach ($n in $dnsTest) { try { Resolve-DnsName $n -ErrorAction Stop | Out-Null } catch { $dnsOk=$false } }

if (-not $icOk) {
  Log "ROOT-CAUSE CANDIDATE: Outbound 443/TCP intermittently blocked or reset (Firewall, Proxy, ISP middlebox) -> investigate security suite, firewall, or proxy."
}
if (-not $dnsOk) {
  Log "ROOT-CAUSE CANDIDATE: DNS resolution failing. Validate DNS servers and local security software."
}

if ($recommendedMTU -and $recommendedMTU -lt 1500) {
  Log "ROOT-CAUSE CANDIDATE: Path MTU less than 1500. Consider setting NIC MTU to $recommendedMTU to avoid TLS resets due to fragmentation."
}

if ($proxyEnabled -eq 1 -or ($winhttp -match 'Proxy Server')) {
  Log "ROOT-CAUSE CANDIDATE: Proxy configuration detected. Verify it is intentional and reachable."
}

# Hosts suspect?
if ($suspect -and $suspect.Count -gt 0) {
  Log "ROOT-CAUSE CANDIDATE: HOSTS overrides for major domains present."
}

# Time skew?
if ($offsetSec) {
  if ([math]::Abs($offsetSec) -gt 60) {
    Log "ROOT-CAUSE CANDIDATE: System time skew >60s impacting TLS."
  }
}

Log "Detailed log saved to: $Log"
# endregion

# region --- Final Branded Banner ---
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                               YOUSTABLE HOSTING                                  " -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Report: $Log" -ForegroundColor Yellow
# endregion