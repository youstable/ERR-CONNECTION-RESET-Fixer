# 🖥️ Find-ERR_CONNECTION_RESET — Windows One-Click Root-Cause Diagnostic

> **A production-grade PowerShell runbook that isolates the true cause of `ERR_CONNECTION_RESET` across network, DNS, proxy, MTU, firewall, time/TLS drift, HOSTS overrides, and browser risk indicators — with branded reporting for “YOUSTABLE HOSTING”.**

---

## 📌 Overview

`Find-youstable-reset-tool.ps1` is a **diagnostics-first** script built for Windows users and sysadmins.  
It systematically checks each possible cause of Chrome/Edge’s infamous **[ERR_CONNECTION_RESET](https://www.youstable.com/blog/how-to-fix-err-connection-reset-error/)** error, logs all findings, and provides clear remediation hints.

At the end, the script prints a **YOUSTABLE HOSTING** banner and saves a **full report** to your Desktop.

---

## 🚀 Features

| Category                          | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| **Connectivity & DNS**            | ICMP/TCP reachability tests, DNS resolution before/after cache flush       |
| **Proxy Intelligence**            | Checks WinINET & WinHTTP proxies, PAC files, auto-detect settings           |
| **Wi-Fi & Link Health**            | Lists saved profiles, active SSID, and link stats                           |
| **MTU / Fragmentation Test**       | Binary-search to find max non-fragmenting payload                           |
| **HOSTS File Hygiene**             | Detects suspicious overrides for key domains                               |
| **Time/TLS Sanity**                | Checks system clock skew vs NTP server                                     |
| **Firewall Posture**               | Reports Windows Firewall profile status                                    |
| **Chrome Indicators**              | Lists policies and installed extensions                                    |
| **Security Scan**                  | Runs Microsoft Defender Quick Scan (Chrome Cleanup Tool replacement)       |
| **Audit-Ready Logs**                | Full timestamped log saved locally                                         |

---

## 🛠️ Why You Might See `ERR_CONNECTION_RESET`

- Misconfigured **proxy** or captive portal  
- **MTU mismatch** causing TCP resets  
- Broken or poisoned **DNS**  
- Aggressive **firewall/security suite**  
- Malicious **HOSTS file entries**  
- Severe **system time drift** invalidating TLS  

---

## 📋 Requirements

- Windows 10/11 or Windows Server 2016+  
- PowerShell 5+  
- **Run as Administrator** for complete coverage  

---

## 📥 Installation

1. Save the script as: youstable-reset-tool.ps1
2. Open **PowerShell as Administrator** in that folder.

---

## ▶️ Usage

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Find-youstable-reset-tool.ps1
