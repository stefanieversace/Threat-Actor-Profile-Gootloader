# Gootloader MITRE ATT&CK Mapping

## Software
- **Gootloader**
- MITRE ID: **S1138**

## Relevant Techniques

### T1189 - Drive-by Compromise
Used when victims are lured to compromised or malicious websites that deliver the payload.

### T1204.001 - User Execution: Malicious Link
User interaction is required to click malicious search results or links leading to download pages.

### T1059.007 - Command and Scripting Interpreter: JavaScript
Gootloader commonly relies on obfuscated JavaScript for execution.

### T1027 - Obfuscated Files or Information
Obfuscation is a defining feature of many Gootloader samples and delivery scripts.

### T1059.001 - Command and Scripting Interpreter: PowerShell
Public reporting has described PowerShell usage in follow-on execution and persistence.

### T1053.005 - Scheduled Task/Job: Scheduled Task
Some infection chains establish persistence using scheduled tasks.

### T1082 - System Information Discovery
Discovery activity may occur before or during follow-on payload execution.

## Notes
This mapping is based on publicly reported behaviour and should be refined further if a specific campaign or sample is being analysed.
