# 🚨 SOC Incident Response - Phishing & DNS Tunneling

## 📊 Overview
Full incident investigation of a sophisticated spear-phishing campaign that compromised a CEO's workstation. Attack included malicious .LNK file, PowerShell reverse shell, and DNS tunneling exfiltration.

## ⏱️ Key Metrics
- **Dwell Time:** 12 minutes
- **True Positive Rate:** 95%
- **Mean Time to Resolve:** 5 minutes 30 seconds
- **Total Alerts:** 11 closed

## 🔗 MITRE ATT&CK Mapping

| Phase | Technique | Description |
|-------|-----------|-------------|
| Initial Access | T1566 | Spear-phishing email with malicious attachment |
| Execution | T1059 | PowerShell execution of reverse shell |
| Command & Control | T1071 | DNS tunneling via ngrok.io |
| Exfiltration | T1048 | Data exfiltration via DNS queries |

## 🔍 Splunk Queries Used
```spl
# Identify initial PowerShell execution
index=powershell.exe Invoke-WebRequest downloading powercat.ps1

# Confirm C2 beaconing via ngrok
index=ngrok.io Outbound connections

# Identify DNS-based exfiltration
index=nslookup.exe Abnormally high volume of DNS lookups
