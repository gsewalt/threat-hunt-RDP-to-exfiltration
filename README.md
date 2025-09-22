<img height="512" alt="unnamed" src="https://github.com/user-attachments/assets/e16a0fc3-0f8d-4b8d-8c66-59844544654d" />

# Threat Hunt Report: RDP Compromise to Data Exfiltration Incident

* **Report ID:** INC-2025-XXXX
* **Analyst:** Gregory Sewalt
* **Report Date:** 2025-09-21
* **Incident Date (observed):** 2025-09-12 → 2025-09-16

---

## Introduction: Scenario Overview

During routine monitoring, unusual RDP login activity was detected on the corporate network. Multiple failed login attempts were observed against systems matching the `flare` naming convention. As a SOC analyst, the goal was to trace these attempts, determine if any were successful, identify attacker behavior post-compromise, and determine the scope of potential data exfiltration.

This investigation walks through the entire attack lifecycle: from initial access to post-exploitation activity, persistence, detection avoidance, and finally exfiltration. The objective was to piece together the attacker’s movements, identify Indicators of Compromise (IOCs), and provide actionable remediation steps.

---

## Platforms and Languages Leveraged

* Windows 10 Virtual Machines (Microsoft Azure)
* EDR Platform: Microsoft Defender for Endpoint
* Kusto Query Language (KQL)
* Remote Desktop Protocol (RDP)

> These were the tools at our disposal to reconstruct the attacker’s journey across the network.

---

## Quick Findings (Key IOCs)

After reconstructing the timeline, several critical IOCs became apparent:

* **Attack Source IP:** `159.26.106.84`
* **Compromised Account:** `slflare`
* **Malicious File:** `msupdate.exe` (PowerShell-launched, suspicious SHA)
* **Persistence Mechanism:** Scheduled task `MicrosoftUpdateSync`
* **Detection Avoidance:** Microsoft Defender folder exclusion `C:\Windows\Temp`
* **C2 / Exfil Destination:** `185.92.220.87` (exfil over port `8081`)
* **Affected Host:** `slflarewinsysmo`

> Each IOC tells a part of the story — from the attacker’s foothold to their method of exfiltrating data without triggering alerts.

---

## Investigation Narrative & KQL Queries

### Query 1 — Initial Access Detection (RDP logons)
**Timeframe:** 2025-09-12 23:50 UTC → 2025-09-13 00:53 UTC
```kql
DeviceLogonEvents
| where ActionType has_any ("LogonFailed", "LogonSuccess")
| where isnotempty(RemoteIP)
| where DeviceName contains "flare"
| where Timestamp between (datetime(2025-09-13 00:00:00) .. datetime(2025-09-16 23:59:59))
| project Timestamp, DeviceName, ActionType, AccountName, RemoteIP
| order by Timestamp asc
```

> Our journey begins by identifying how the attacker first approached the network. Repeated failed logins set off alarms, revealing a classic brute force attempt. Finally, the account `slflare` succeeds, opening the door to further compromise.
<img width="1107" height="167" alt="image1" src="https://github.com/user-attachments/assets/649a5de4-2938-452a-874b-c60641cbf684" />


---

### Query 2 — Malicious Execution (`msupdate.exe`)
**Execution Time:** 2025-09-16 12:38:40 UTC
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-09-16 11:40:57) .. datetime(2025-09-16 23:59:59))
| where DeviceName == "slflarewinsysmo"
| where AccountName == "slflare"
| where FileName endswith ".exe"
| where FolderPath has_any ("Download", "Temp", "Public")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

> Once inside, the attacker moves quickly to establish malicious execution. `msupdate.exe` is launched via PowerShell with a bypass policy — a telltale sign of unauthorized activity. The file hash didn’t match official Microsoft binaries, confirming suspicion.
<img width="922" height="87" alt="image2" src="https://github.com/user-attachments/assets/a6e739c2-8614-43c0-9a17-55aff6729875" />


---

### Query 3 — Persistence (Scheduled Task registration)
**Scheduled Task Creation:** 2025-09-16 12:39:45 UTC
```kql
DeviceRegistryEvents
| where DeviceName == "slflarewinsysmo"
| where Timestamp between (datetime(2025-09-16 11:38:40) .. datetime(2025-09-16 12:50:59))
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, ActionType, RegistryKey
| order by Timestamp asc
```

> Persistence is key for attackers. We observed the creation of a scheduled task, “MicrosoftUpdateSync,” immediately following malicious execution — a silent foothold to maintain access after reboot.
<img width="843" height="204" alt="image3" src="https://github.com/user-attachments/assets/f1a4db33-0b90-4e64-b2f3-a3b18d8eef1b" />


---

### Query 4 — Detection Avoidance (Defender exclusion)
**Registry Exclusion Added:** 2025-09-16 12:39:48 UTC
```kql
DeviceRegistryEvents
| where DeviceName == "slflarewinsysmo"
| where Timestamp between (datetime(2025-09-16 12:39:45) .. datetime(2025-09-16 12:45:00))
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
```

> The attacker demonstrates awareness of detection mechanisms by adding `C:\Windows\Temp` to Defender exclusions — allowing their scripts and files to operate without raising alarms.
<img width="893" height="160" alt="image4" src="https://github.com/user-attachments/assets/b9c8a340-14ed-4268-8b0a-de90c384bf8e" />


---

### Query 5 — Host Enumeration (built-in tools)
**Enumeration Start:** 2025-09-16 12:40:28 UTC
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-09-16 12:39:48) .. datetime(2025-09-16 12:50:00))
| where DeviceName == "slflarewinsysmo"
| where AccountName == "slflare"
| where FileName in ("cmd.exe", "powershell.exe", "wmic.exe", "net.exe", "systeminfo.exe", "ipconfig.exe", "whoami.exe", "tasklist.exe")
| where ProcessCommandLine has_any ("systeminfo","ipconfig","net user","net localgroup","whoami","tasklist","Get-ComputerInfo","Get-WmiObject","Get-NetIPConfiguration")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

> Before exfiltrating data, the attacker surveys the environment. Using built-in Windows commands, they gather system information, user accounts, and network details to identify valuable targets.
<img width="1007" height="131" alt="image5" src="https://github.com/user-attachments/assets/1e6b1842-9b79-4166-9e32-e6bfbbb46ccf" />


---

### Query 6 — Data Archive Creation (for exfil)
**Archive Creation Times:**
backup_sync.zip: 2025-09-16 12:41:30 UTC
employee-data-20250916204931.zip: 2025-09-16 13:49:43 UTC
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-09-16 12:40:28) .. datetime(2025-09-16 14:00:00))
| where ActionType == "FileCreated"
| where DeviceName == "slflarewinsysmo"
| where FileName has_any (".zip", ".rar", ".7z", ".7zip")
| where FolderPath has_any ("Temp", "AppData", "ProgramData", "Public")
| project Timestamp, FileName, FolderPath, InitiatingProcessAccountName
| order by Timestamp asc
```

> With reconnaissance complete, the attacker packages files into compressed archives for exfiltration. Two archives are created, marking the preparation stage for stealing sensitive data.
<img width="1156" height="100" alt="image6" src="https://github.com/user-attachments/assets/b0779ad2-7363-4dba-b993-df53d0af7f8e" />


---

### Query 7 — External Server Connection & Data Exfiltration
**Exfiltration Times:**
Port 80: 2025-09-16 12:42:17 UTC
Port 8081: 2025-09-16 12:42:26 UTC
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-09-16 12:41:00) .. datetime(2025-09-16 13:00:00))
| where DeviceName == "slflarewinsysmo"
| where InitiatingProcessFileName in ("powershell.exe", "svchost.exe", "msupdate.exe")
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp asc
```

> The final act: communication with the attacker’s server. Connections to `185.92.220.87` over port 80 (C2) and port 8081 (data exfiltration) confirm that files have left the environment.
<img width="1159" height="100" alt="image7" src="https://github.com/user-attachments/assets/560cc702-d7fa-49ff-97cf-2d9cbfd06b6f" />


---

## Chronological Event Timeline (Narrative)

1. **2025-09-12:** Brute force attempts commence, probing RDP logins.
2. **2025-09-13:** Failed attempts continue; SOC monitoring picks up anomalies.
3. **2025-09-16 11:40:57:** Successful RDP login; attacker gains initial access.
4. **2025-09-16 12:38:40:** Malicious executable launched.
5. **2025-09-16 12:39:45:** Scheduled task for persistence created.
6. **2025-09-16 12:39:48:** Defender exclusion added.
7. **2025-09-16 12:40:28:** Host enumeration begins.
8. **2025-09-16 12:41:30:** First archive created.
9. **2025-09-16 12:42:17 → 12:42:26:** Exfiltration begins and completes.
10. **2025-09-16 13:49:43:** Final archive created; last observed activity.

> This timeline reconstructs the attack step by step — a digital footprint of the adversary’s path.

---

## Investigation Summary

**Attack Narrative:**
An external actor brute-forced RDP access into a Windows host. After gaining access, they deployed malicious binaries, established persistence, evaded detection, enumerated host resources, compressed sensitive data, and exfiltrated files to an external IP. The attack was deliberate and methodical, demonstrating awareness of defensive measures.

**Impact Level:** High — confirmed exfiltration and persistent foothold.

---

## Response Taken

* Host isolated and compromised account disabled.
* Malicious files quarantined; forensic images collected.
* Firewall blocks applied to attacker IPs.
* Internal stakeholders notified; incident documented.

---

## Recommendations

**Immediate Actions:**
Block attacker IPs, quarantine malicious files, remove scheduled tasks, revert Defender exclusions, rotate credentials.

**Short-term (1–30 days):**
Enable MFA, restrict RDP exposure, audit Temp/Public folders, tighten brute-force detection.

**Long-term (30+ days):**
Implement JIT RDP access, improve anomaly detection, strengthen SOC alerts for Defender exclusions and suspicious scheduled tasks.

**Detection Enhancements:**

* Alert on failed login bursts followed by successful logon from unusual IPs.
* Monitor scheduled tasks created by non-admin users.
* Watch for Defender exclusions added outside policy.
* Alert on outbound connections to uncommon ports (e.g., 8081).

---

## MITRE ATT&CK Mapping

| Phase | Observed Activity | MITRE Technique ID | Technique Name |
|-------|-----------------|-----------------|----------------|
| **Initial Access** | RDP brute-force leading to successful login | T1078 | Valid Accounts |
| **Execution** | Malicious `msupdate.exe` executed via PowerShell | T1059.001 | PowerShell |
| **Persistence** | Scheduled task `MicrosoftUpdateSync` created | T1053.005 | Scheduled Task/Job: S

### Notes

This narrative-driven investigation demonstrates how detailed SOC monitoring, careful log analysis, and KQL proficiency can reconstruct an entire attack lifecycle from initial RDP brute force to data exfiltration.
