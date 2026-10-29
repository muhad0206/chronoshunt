# ChronosHunt ⏳🔍
### SOC Threat Hunting & DFIR Timeline Reconstructor

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise%20v14-red.svg)](https://attack.mitre.org)
[![DFIR Framework](https://img.shields.io/badge/DFIR-Artifact%20Correlation-purple.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **ChronosHunt** is an enterprise-grade Digital Forensics and Incident Response (DFIR) threat hunting engine. It correlates disparate endpoint telemetry (Sysmon, Windows Prefetch, PowerShell ScriptBlocks, Windows Security Logs, and Web Server access logs) into a unified, microsecond-accurate **Adversary Attack Timeline** with automated dwell-time analytics and critical pivot point detection.

---

## 📌 The DFIR Problem: Disjointed Artifact Chaos
During a major cyber incident (such as a ransomware outbreak or state-sponsored intrusion), incident responders and SOC Tier-3 threat hunters extract multiple heterogeneous artifact dumps:
* **Sysmon EVTX**: Process creation and network connections.
* **Windows Prefetch (`.pf`)**: Historical application execution frequency and timestamps.
* **PowerShell ScriptBlock (Event 4104)**: In-memory scripts and de-obfuscated commands.
* **Security Event Logs**: Network logons (4624 Type 3) and privilege assignments (4672).
* **Web Server Logs**: Initial web shell or CVE exploitation attempts.

Because each artifact has different schemas, varying time formats, and isolated contexts, investigators spend **critical hours manually stitching together CSV spreadsheets**.

**ChronosHunt** automates this forensic reconstruction in seconds:
1. Normalizes multi-source forensic evidence into UTC-aligned `TimelineEvent`s.
2. Calculates exact **Attacker Dwell Time** (from initial foothold to ransomware detonation/exfiltration).
3. Automatically detects **Adversary Pivot Points** (Office macro execution, LSASS memory dumps, shadow copy deletion, lateral SMB jumps).
4. Generates an exportable **DFIR Executive Investigation Brief** in Markdown.

---

## 🏗️ System Architecture

```
                    [ Disparate Forensic Artifact Dumps ]
        (Sysmon EVTX, Windows Prefetch, PS 4104, Security 4624, IIS Logs)
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │   ChronosHunt Normalizer Core     │
                     │  (Timestamp & Field Unification)  │
                     └─────────────────┬─────────────────┘
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
  ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
  │  Causality Engine │      │   Dwell Time      │      │  Adversary Pivot  │
  │& Lineage Tracker  │      │   Calculator      │      │  Detection Filter │
  │(Parent-Child PIDs)│      │(Foothold to Action│      │(LSASS, VSS, Macros│
  └─────────┬─────────┘      └─────────┬─────────┘      └─────────┬─────────┘
            │                          │                          │
            └──────────────────────────┼──────────────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │   Chronological Timeline Engine   │
                     │  (Kill-Chain Phase & MITRE Map)   │
                     └─────────────────┬─────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
┌───────────────────────────────┐                 ┌───────────────────────────────┐
│     DFIR Threat Hunter UI     │                 │   Exportable Briefing Docs    │
│ (Interactive Time Scrub,      │                 │ (Markdown Incident Brief,     │
│  Kill-Chain Pills, Pivots)    │                 │  Scoping Tables, CSV/JSON)    │
└───────────────────────────────┘                 └───────────────────────────────┘
```

---

## ✨ Key Capabilities

### 1. Multi-Artifact Ingestion & Normalization
* **Sysmon (Event ID 1 & 3)**: Extracts parent-child process hierarchy, command arguments, and network sockets.
* **Windows Prefetch (`.pf`)**: Ingests execution run counts and executable path provenance.
* **PowerShell ScriptBlock (Event 4104)**: Flags in-memory Base64 downloads and unrolled script executions.
* **Windows Security Logs (4624 & 4672)**: Correlates lateral network logons (Type 3) and `SeDebugPrivilege` assignment.
* **Web Server Access Telemetry**: Correlates web shell execution (`w3wp.exe` $\rightarrow$ `cmd.exe`).

### 2. Microsecond-Accurate Timeline & Delta Tracking
* Sorts multi-host evidence chronologically.
* Computes time deltas relative to the initial foothold (e.g. `+00m 00s Foothold` $\rightarrow$ `+04m 10s Recon` $\rightarrow$ `+14m 42s Ransomware Execution`).

### 3. Automated Adversary Pivot Detection
Automatically tags breakthrough moments where an attacker escalated their intrusion:
* **Initial Access**: Macro-enabled document spawning script shells.
* **Credential Access**: Sysinternals `procdump.exe` or `mimikatz.exe` targeting `lsass.exe`.
* **Inhibit System Recovery**: Volume shadow copy deletion via `vssadmin.exe delete shadows /all /quiet`.
* **Lateral Movement**: Pass-the-Hash / PsExec execution across internal subnets.
* **Active Directory Recon**: Mass object enumeration via `SharpHound.exe` or `BloodHound`.

### 4. Dwell Time Analytics
Calculates the exact duration between adversary initial access and remediation containment, producing forensic metrics for cyber insurance and incident response post-mortems.

---

## 🎯 Pre-Loaded Enterprise Breach Cases

| Case ID | Investigation Title | Threat Actor | Dwell Time | Critical Pivots |
| :--- | :--- | :--- | :---: | :--- |
| **`CASE-2026-081`** | **BlackCat (ALPHV) Ransomware Outbreak** | FIN7 / ALPHV Affiliate | `14m 42s` | Web shell $\rightarrow$ Certutil loader $\rightarrow$ LSASS dump $\rightarrow$ VSSAdmin shadow delete |
| **`CASE-2026-094`** | **APT29 (Cozy Bear) Phishing to Exfil** | APT29 (Midnight Blizzard) | `32m 44s` | Word macro stager $\rightarrow$ Scheduled task persistence $\rightarrow$ SharpHound recon $\rightarrow$ Cloud exfil |
| **`CASE-2026-105`** | **Finance Insider Malicious IP Theft** | Disgruntled Insider | `9m 40s` | USB Robocopy mass export $\rightarrow$ Event log wiping attempt (`wevtutil cl`) |

---

## 🚀 Quick Start

### 1. Prerequisites
* Python 3.10+
* Git

### 2. Installation
```bash
# Clone repository
git clone https://github.com/muhad0206/chronoshunt.git
cd chronoshunt

# Install dependencies
pip install -r requirements.txt
```

### 3. Launch ChronosHunt
```bash
python3 run.py
```
Open your browser and navigate to:
```
http://localhost:8080
```
Interactive API documentation is available at `http://localhost:8080/docs`.

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/cases` | Retrieve all breach investigations |
| `GET` | `/api/cases/{id}` | Retrieve comprehensive case timeline and dwell time |
| `POST` | `/api/cases` | Reconstruct attack timeline from raw JSON artifacts |
| `GET` | `/api/cases/{id}/export` | Export formatted Markdown DFIR Investigation Brief |
| `GET` | `/api/metrics` | Retrieve DFIR KPIs (average dwell time, correlated artifacts) |
| `POST` | `/api/cases/load-samples` | Reset sample breach datasets |

---

## 💼 Resume & Portfolio Highlights

* **Digital Forensics & Incident Response (DFIR)**:
  > *"Developed **ChronosHunt**, an endpoint artifact correlation engine that normalizes Sysmon, Prefetch, PowerShell 4104, and Windows Security logs into unified chronological attack timelines."*

* **Threat Hunting & Dwell-Time Analytics**:
  > *"Engineered automated adversary pivot detection algorithms mapping multi-stage intrusions across MITRE ATT&CK kill-chain phases, calculating exact attacker dwell time from initial access to ransomware execution."*

* **Forensic Reporting & Incident Scoping**:
  > *"Automated executive DFIR brief generation, synthesizing affected hosts, compromised accounts, and C2 infrastructure into audit-ready Markdown and CSV incident reports."*

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
