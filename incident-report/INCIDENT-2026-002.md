# 🚨 SECURITY INCIDENT REPORT - IR-2026-001

## 📋 Executive Summary
**Date:** 2026-01-30  
**Severity:** High  
**Status:** Contained  
**Affected Systems:** Web Server (192.168.1.100), Domain Controller (DC01), Linux Server (Linux-server01)  
**Attack Type:** Brute Force → Privilege Escalation → Data Exfiltration  

## 🎯 Incident Timeline
| Time (UTC) | Event | Evidence |
|------------|-------|----------|
| 08:15 | First failed login attempt | Splunk: `EventCode=4625` |
| 08:20-08:45 | Brute force attack (500+ attempts) | Firewall logs, Splunk alert |
| 08:50 | Successful login (compromised admin creds) | `EventCode=4624` |
| 09:05 | Privilege escalation detected | Domain Admin events (4728, 4732) |
| 09:15 | Data exfiltration begins | Large outbound transfer detected |
| 09:30 | SOC alerted, investigation starts | Splunk dashboard trigger |
| 09:45 | Containment actions taken | Hosts isolated, creds reset |
| 10:00 | Incident contained | No further malicious activity |

## 🔍 Detection & Investigation

### 1. Brute Force Attack Detection
**Splunk Query:**
```splunk
index=windows EventCode=4625 
| stats count by IpAddress, TargetUserName 
| where count > 20
```
**Finding:** 523 failed login attempts from IP `185.153.196.42` to `admin` account.

### 2. Privilege Escalation Detection  
**Splunk Query:**
```splunk
(source="*" ("Domain Admin" OR "4728" OR "4732" OR "4756" OR "runas.exe" OR "PsExec"))
OR (source="*linux*" "sudo:" ("/bin/bash" OR "passwd" OR "useradd" OR "shadow"))
| stats count as suspicious_events by host
| where suspicious_events > 0
```
**Finding:** Privilege escalation detected on `DC01` (4 events) and `Linux-server01` (4 events).

### 3. Data Theft Detection
**Splunk Query:**
```splunk
index=proxy_logs dest_ip=185.153.196.42
| stats sum(bytes) as total_bytes
| where total_bytes > 100000000
```
**Finding:** 150MB of data transferred to attacker's IP.

## 📸 Forensic Evidence

### Splunk Query Results - Privilege Escalation Detection
![Privilege Escalation Detection Results](screenshots/privilege-escalation-detection.png)

*Figure 1: Splunk detection query showing privilege escalation events across Windows and Linux systems.*

## 🛡️ Containment Actions
1. **Immediate:**
   - Isolated affected servers from network
   - Blocked malicious IP (`185.153.196.42`) at firewall
   - Reset all compromised credentials

2. **Forensic Preservation:**
   - Disk images captured for analysis
   - Memory dumps of affected systems
   - Log collection preserved

## 🔧 Remediation Steps
- [x] Patch vulnerable web application
- [x] Implement WAF rules to block suspicious uploads
- [x] Deploy EDR on all critical servers
- [x] Enable MFA for administrative accounts
- [ ] Conduct security awareness training

## 📊 MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Valid Accounts | T1078 |
| Privilege Escalation | Domain Groups | T1069.002 |
| Defense Evasion | Indicator Removal | T1070 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

## 🎓 Lessons Learned
1. **Detection Gap:** No alert for rapid failed logins
2. **Prevention Gap:** Excessive privileges on service accounts
3. **Response Gap:** 45-minute delay from compromise to detection

## 📈 Recommendations
1. Implement SIEM correlation rule for brute force patterns
2. Apply principle of least privilege to all accounts
3. Establish 15-minute SLA for high-severity alerts
4. Conduct tabletop exercises quarterly

---
**Report Generated:** 2026-01-30  
**Investigator:** Renaldi  
**SOC Team:** Blue Team Alpha  
**Tools Used:** Splunk SIEM, Wireshark, VirusTotal
