# Gootloader Malware OSINT & Detection Analysis

## Overview
This repository contains an open-source intelligence and detection-focused analysis of **Gootloader**, a malware family associated with **SEO poisoning**, **malicious ZIP/JavaScript delivery**, and **follow-on payload deployment**. The goal of this project is to document the threat actor tradecraft, map behaviours to **MITRE ATT&CK**, and provide practical **Microsoft Sentinel KQL detections**.

## Why this project matters
Gootloader is relevant to modern SOC and Threat Intelligence work because it combines:
- Initial access tradecraft
- User-driven infection via malicious search results
- Obfuscated JavaScript execution
- PowerShell activity
- Persistence techniques such as scheduled tasks
- Delivery of additional payloads such as Cobalt Strike and ransomware-enabling access

## Objectives
- Summarise what Gootloader is and how it operates
- Document the infection chain from lure to execution and persistence
- Collect and organise indicators of compromise (IOCs)
- Map observed behaviours to MITRE ATT&CK
- Develop starter Microsoft Sentinel detections
- Present findings in a format useful for SOC and Threat Intelligence teams

## Scope
This project is based on publicly available reporting and is intended for educational, defensive, and portfolio purposes only.

## Infection Chain Summary
1. Victim searches for a business, legal, financial, or niche topic online
2. SEO-poisoned or compromised site appears in search results
3. Victim downloads a malicious ZIP archive
4. Archive contains an obfuscated JavaScript file
5. JavaScript executes via Windows Script Host
6. Additional scripts or payloads are retrieved and executed
7. Persistence may be established, including scheduled task abuse
8. Follow-on activity may include PowerShell, Cobalt Strike, or ransomware-related access

## Repository Structure
```text
gootloader-osint-analysis/
│
├── README.md
├── report/
│   └── gootloader-threat-report.md
├── indicators/
│   └── iocs.csv
├── detection/
│   └── sentinel-kql-queries.kql
├── mitre-mapping/
│   └── attack-techniques.md
└── visuals/
