<img height="512" alt="unnamed" src="https://github.com/user-attachments/assets/e16a0fc3-0f8d-4b8d-8c66-59844544654d" />


# THREAT HUNT – RDP Compromise Incident SOC Investigation Report


**Report ID:** INC-2025-XXXX  
**Analyst:** Gregory Sewalt  
**Date:** 2025-09-21  
**Incident Date:** 2025-09-14  

---

## 1. Findings

**Key Indicators of Compromise (IOCs):**  

- **Attack Source IP:** 159.26.106.84  
- **Compromised Account:** slflare  
- **Malicious File:** msupdate.exe  
- **Persistence Mechanism:**  
  - Scheduled task creation for automated payload execution post-intrusion (“MicrosoftUpdateSync”)  
  - Microsoft Defender folder scan exclusion (C:\Windows\Temp)  
- **C2 Server:** 185.92.220.87  
- **Exfiltration Destination:** 185.92.220.87:8081  

**KQL Queries Used:**  

**Query 1 – Initial Access Detection**  
DeviceLogonEvents  
| where ActionType has_any ("LogonFailed", "LogonSuccess")  
| where isnotempty(RemoteIP)  
| where DeviceName contains "flare"  
| where Timestamp between (datetime(2025-09-13 00:00:00) .. datetime(2025-09-16 23:59:59))  
| project Timestamp, DeviceName, ActionType, AccountName, RemoteIP  
| order by Timestamp asc  

**Results:**  
- Extensive failed logons from 9/12 until 12:53:53 AM on 9/13.  
- First successful login on 9/16 from IP `159.26.106.84` using account **slflare** at 11:40:57 AM.  

---

**Query 2 – Malicious Execution**  
DeviceProcessEvents  
| where Timestamp between (datetime(2025-09-16 11:40:57) .. datetime(2025-09-16 23:59:59))  
| where DeviceName == "slflarewinsysmo"  
| where AccountName == "slflare"  
| where FileName endswith ".exe"  
| where FolderPath has_any ("Download", "Temp", "Public")  
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName  
| order by Timestamp asc  

**Results:**  
- Execution logs for **DismHost.exe** and **msupdate.exe**.  
- `msupdate.exe` executed at 12:38:40 PM in PowerShell: `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`.  
- File path and SHA hash inconsistent with legitimate Microsoft updates.  

---

**Query 3 – Persistence Detection**  
DeviceRegistryEvents  
| where DeviceName == "slflarewinsysmo"  
| where Timestamp between (datetime(2025-09-16 13:38:40) .. datetime(2025-09-16 12:50:59))  
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"  
| where ActionType == "RegistryValueSet" or ActionType == "RegistryKeyCreated"  
| project Timestamp, ActionType, RegistryKey  
| order by Timestamp asc  

**Results:**  
- Two registry key creations; post-malicious execution, one at 12:39:45 PM reveals scheduled task **“MicrosoftUpdateSync”**.  

---

**Query 4 – Ongoing Detection Avoidance**  
DeviceRegistryEvents  
| where DeviceName == "slflarewinsysmo"  
| where Timestamp between (datetime(2025-09-16 19:39:45) .. datetime(2025-09-16 23:59:59))  
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"  
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")  
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData  
| order by Timestamp asc  

**Results:**  
- Registry value set at 12:39:48 PM to exclude **C:\Windows\Temp** from Defender scans.  

---

**Query 5 – Host Enumeration**  
DeviceProcessEvents  
| where Timestamp between (datetime(2025-09-16 19:39:48) .. datetime(2025-09-16 23:59:59))  
| where DeviceName == "slflarewinsysmo"  
| where AccountName == "slflare"  
| where FileName in ("cmd.exe", "powershell.exe", "wmic.exe", "net.exe", "systeminfo.exe", "ipconfig.exe", "whoami.exe", "tasklist.exe")  
| where ProcessCommandLine has_any ("systeminfo","ipconfig","net user","net localgroup","whoami","tasklist","Get-ComputerInfo","Get-WmiObject","Get-NetIPConfiguration")  
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine  
| order by Timestamp asc  

**Results:**  
- Multiple host enumeration commands executed; earliest at 12:40:28 PM using `cmd.exe /c systeminfo`.  

---

**Query 6 – Data Archive Creation for Exfiltration**  
DeviceFileEvents  
| where Timestamp between (datetime(2025-09-16 19:40:28) .. datetime(2025-09-16 23:59:59))  
| where ActionType == "FileCreated"  
| where DeviceName == "slflarewinsysmo"  
| where FileName has_any (".zip", ".rar", ".7z", ".7zip")  
| where FolderPath has_any ("Temp", "AppData", "ProgramData")  
| order by Timestamp asc  

**Results:**  
- Two archives created for exfiltration:  
  - `backup_sync.zip` at 12:41:30 PM  
  - `employee-data-20250916204931.zip` at 1:49:43 PM  

---

**Query 7 – External Server Connection and Data Exfiltration**  
DeviceNetworkEvents  
| where Timestamp between (datetime(2025-09-16 19:41:30) .. datetime(2025-09-16 23:59:59))  
| where DeviceName == "slflarewinsysmo"  
| where InitiatingProcessFileName in ("powershell.exe", "svchost.exe")  
| where isnotempty(RemoteIP)  
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, Protocol  
| order by Timestamp asc  

**Results:**  
- Two outbound connections to `185.92.220.87`:  
  - Port 80 at 12:42:17 PM (C2 setup)  
  - Port 8081 at 12:42:26 PM (Data exfiltration)  

---

## 2. Investigation Summary

**What Happened:**  
- RDP brute force attack led to account compromise (`slflare`).  
- Malicious binary executed (`msupdate.exe`) and persistence established.  
- Data was archived and exfiltrated to an external server.

**Attack Timeline:**  
- **Started:** 2025-09-12 UTC (first failed attempts)  
- **Ended:** 2025-09-16 UTC (final exfiltration)  
- **Duration:** 4 days  
- **Impact Level:** High  

---

## 3. Who, What, When, Where, Why, How

**Who:**  
- Attacker IP: 159.26.106.84  
- Victim Account: slflare  
- Affected System: slflarewinsysmo  
- Impact on Users: Potential data loss  

**What:**  
- Attack Type: RDP brute force leading to system compromise  
- Malicious Activities: Execution of `msupdate.exe`, persistence, host enumeration, archive creation, data exfiltration  

**When:**  
- First Malicious Activity: 2025-09-16 11:40:57 UTC  
- Last Observed Activity: 2025-09-16 13:49:43 UTC  
- Detection Time: 2025-09-16 14:00 UTC  
- Total Attack Duration: ~4 days  
- Is it still active? No  

**Where:**  
- Target System: slflarewinsysmo  
- Attack Origin: Unknown, IP 159.26.106.84  
- Network Segment: Internal Windows domain  
- Affected Directories/Files: C:\Users\Public, C:\Windows\Temp  

**Why:**  
- Likely Motive: Data theft  
- Target Value: User data and sensitive organizational files  

**How:**  
- Initial Access Method: RDP brute force  
- Tools/Techniques Used: PowerShell, malicious binaries, scheduled tasks  
- Persistence Method: Scheduled Task “MicrosoftUpdateSync”, Defender exclusion  
- Data Collection Method: Host enumeration, file compression  
- Communication Method: Outbound connections to C2 server  

---

## 4. Recommendations

**Immediate Actions:**  
- Block attacker IPs at perimeter (`159.26.106.84`, `185.92.220.87`)  
- Quarantine `msupdate.exe` and remove scheduled tasks  
- Reset credentials for slflare  

**Short-term Improvements (1–30 days):**  
- Enforce MFA on all RDP sessions  
- Audit all local and domain accounts for exposure  
- Monitor critical folders (Temp, Public)  

**Long-term Security Enhancements:**  
- Implement Just-in-Time RDP access  
- Disable unnecessary internet-facing RDP  
- Deploy detection rules for Defender exclusions and suspicious scheduled tasks  

**Detection Improvements:**  
- Alerts for multiple failed RDP logons followed by success  
- Alerts for scheduled task creation with unusual names  
- Alerts for Defender folder exclusion changes  
- Monitor outbound traffic on uncommon ports like 8081  

**Report Status:** Complete  
**Next Review:** TBD  
**Distribution:** Cyber Range  
