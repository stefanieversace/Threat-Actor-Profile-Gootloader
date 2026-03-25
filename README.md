# Gootloader OSINT & Detection Analysis

## Overview
This project presents an open-source intelligence (OSINT) and detection-focused analysis of **Gootloader**, a malware delivery framework associated with SEO poisoning and JavaScript-based initial access.

Gootloader is commonly used to deliver follow-on payloads, including post-exploitation frameworks such as Cobalt Strike, making it highly relevant for SOC analysts and threat intelligence teams.

This project combines threat intelligence, MITRE ATT&CK mapping, and Microsoft Sentinel detection engineering to demonstrate how publicly available reporting can be translated into practical defensive insights.

---

## Infection Chain

1. Victim searches for business, legal, or niche documents online  
2. SEO-poisoned or compromised website appears in search results  
3. Victim downloads a malicious ZIP archive  
4. Archive contains an obfuscated JavaScript file  
5. JavaScript executes via Windows Script Host (wscript/cscript)  
6. Additional payloads or scripts are retrieved and executed  
7. PowerShell may be used for further execution  
8. Persistence may be established (e.g., scheduled tasks)  
9. Follow-on activity may include Cobalt Strike or ransomware access  

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name |
|-------------|--------------|
| T1189 | Drive-by Compromise |
| T1204.001 | User Execution: Malicious Link |
| T1059.007 | Command and Scripting Interpreter: JavaScript |
| T1027 | Obfuscated Files or Information |
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1053.005 | Scheduled Task/Job |
| T1082 | System Information Discovery |

---

## Key Findings

- Gootloader relies heavily on **SEO poisoning** to achieve initial access  
- Infection begins with **legitimate user behaviour**, making prevention difficult  
- Execution commonly involves **obfuscated JavaScript via Windows Script Host**  
- **PowerShell activity** is often observed in follow-on stages  
- Persistence may be achieved using **scheduled tasks**  
- Gootloader infections can act as a **gateway to larger compromises**, including ransomware  

---

## Analyst Insights

Gootloader highlights a critical weakness in traditional security controls: over-reliance on prevention in user-driven attack paths.

Because the infection begins with legitimate search behaviour and trusted-looking websites, preventative controls alone may fail.

Detection should therefore prioritise behavioural signals, particularly:
- Script interpreter activity  
- Process chaining (wscript → PowerShell)  
- Execution from user-controlled directories  

This reinforces the importance of layered detection and user awareness.

---

## Detection Strategy

The following detections are designed to identify behavioural patterns associated with Gootloader rather than relying solely on static indicators.

Focus areas include:
- Script execution from user directories  
- PowerShell spawned from script interpreters  
- Obfuscated command-line activity  
- Scheduled task creation  
- Suspicious parent-child process relationships  

---

## Detection Queries (Microsoft Sentinel KQL)

```kusto
// Suspicious JavaScript execution from user directories
SecurityEvent
| where EventID == 4688
| where NewProcessName has_any ("wscript.exe", "cscript.exe")
| where CommandLine has_any (".js", ".jse")
| where CommandLine has_any ("AppData", "Temp", "Downloads", "Desktop")
| project TimeGenerated, Computer, Account, ParentProcessName, NewProcessName, CommandLine

// PowerShell spawned from script interpreters
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where ParentProcessName has_any ("wscript.exe", "cscript.exe")
| project TimeGenerated, Computer, Account, ParentProcessName, NewProcessName, CommandLine

// Scheduled task creation
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine has_any ("schtasks", "Register-ScheduledTask")
| project TimeGenerated, Computer, Account, ParentProcessName, NewProcessName, CommandLine

// Obfuscated PowerShell indicators
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine has_any ("-enc", "FromBase64String", "IEX", "DownloadString", "Hidden")
| project TimeGenerated, Computer, Account, ParentProcessName, NewProcessName, CommandLine

## SOC Analyst Playbook

### Alert Scenario
A security alert is triggered indicating suspicious script execution involving `wscript.exe` or `cscript.exe`, potentially originating from a user directory such as Downloads or AppData.

---

### Step 1: Initial Triage
- Review process creation logs (Event ID 4688)
- Identify:
  - Parent process
  - Command line arguments
  - File execution path
- Check if execution originated from:
  - Downloads
  - AppData
  - Temp directories

---

### Step 2: Investigate Process Chain
- Look for suspicious parent-child relationships:
  - `explorer.exe → wscript.exe`
  - `wscript.exe → powershell.exe`
- Identify any follow-on execution such as:
  - PowerShell activity
  - Additional script execution
  - Suspicious binaries

---

### Step 3: Command Line Analysis
- Look for indicators of obfuscation:
  - Encoded commands (`-enc`)
  - Base64 strings
  - Use of `IEX` or `DownloadString`
- Identify any external connections or payload retrieval attempts

---

### Step 4: Persistence Checks
- Investigate scheduled task creation:
  - `schtasks`
  - `Register-ScheduledTask`
- Review registry changes if available
- Check for unusual autorun entries

---

### Step 5: Scope the Incident
- Identify:
  - Other affected hosts
  - Similar command-line patterns across environment
  - Related alerts within the same timeframe
- Pivot on:
  - Username
  - Hostname
  - File hash (if available)

---

### Step 6: Containment Actions
- Isolate affected host if malicious activity is confirmed
- Terminate suspicious processes
- Block associated indicators (domains, hashes, IPs)
- Reset compromised credentials if necessary

---

### Step 7: Escalation
Escalate to Incident Response if:
- Evidence of lateral movement
- C2 communication detected
- Persistence mechanisms confirmed
- Additional payloads (e.g., Cobalt Strike) identified

---

### Step 8: Documentation
- Record:
  - Timeline of events
  - Affected systems
  - Indicators observed
  - Actions taken
- Update detection rules if gaps are identified

---

### Analyst Note
Gootloader infections often represent initial access rather than a complete attack. Even if activity appears limited, treat it as a potential precursor to a larger compromise.

Sources
Microsoft Security Intelligence – Gootloader
MITRE ATT&CK (S1138)
Red Canary Threat Detection Report
Mandiant Threat Intelligence

Disclaimer

This project is intended for educational and defensive security purposes only. All information is derived from publicly available sources. No offensive use is intended.
