# Telemetry Windows: Hybrid ECA & Offline EDR Reporting

**Telemetry Windows** is a specialized PowerShell-based forensic tool designed for high-speed **Early Case Assessment (ECA)** combined with deep **Offline EDR (Endpoint Detection and Response)** telemetry. 

It bridges the gap between traditional forensic imaging and live response by providing a comprehensive, human-readable snapshot of a system's state, security posture, and suspicious indicators without requiring a persistent agent.

---

## 🚀 Key Concepts

### 1. Early Case Assessment (ECA)
The script rapidly gathers high-value forensic artifacts to answer the "First 10 Questions" of an investigation:
- **Inventory**: Hardware, OS version, users, and installed software.
- **Persistence**: Auto-start keys, scheduled tasks, and services.
- **Evidence of Execution**: Amcache, Prefetch patterns (via telemetry), and UserAssist.
- **Connectivity**: Network shares, RDP settings, and firewall status.
- **Mobile History**: Connection history of iOS and Android devices.

### 2. Offline EDR Intelligence
Unlike static collection tools, Telemetry Windows performs active correlation and threat hunting:
- **Event Correlation**: Analyzes Security, System, PowerShell, and Sysmon logs to identify patterns of lateral movement, credential dumping, and execution.
- **Threat Hunt Snapshots**: Executes dozens of built-in "Discovery" commands to verify current system behavior (e.g., active network connections, process command lines).
- **Integrity & Auditing**: Validates auditing levels (`AuditPol`) and logs all actions to a structured JSONL for post-processing.

---

## 💎 Premium Reporting

The tool produces high-fidelity HTML reports designed for senior investigators and stakeholders:

- **Inventory Dashboard**: A visual overview of the system, including a **Vertical DFIR Timeline** (CodePen style) and categorized security sections.
- **StatusLog & Indicator Cards**: Real-time health metrics including RAM usage, Disk status, and counts of high-priority security events.
- **Indicator Scoring**: Color-coded alerts (Red/Yellow/Info) based on registry settings and event log findings.
- **Volume Analysis**: Charts comparing original artifact sizes vs. compressed evidence totals.

---

## 🛠 Usage

Run from an **Administrative PowerShell terminal**:

```powershell
# Enable file for execution
Unblock-File .\telemetry_windows.ps1

# Bypass the police for execution
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Standard execution (includes standard forensic collection)
.\telemetry_windows.ps1

# Advanced analysis with verbose auditing
.\telemetry_windows.ps1 -AuditLevel Verbose

# Target specific stages (e.g., Full, Exact, Lite)
.\telemetry_windows.ps1 -Stage FullExact
```

### Parameters
- `-Stage`: Selection of collection depth (`FullExact`, `Lite`, etc.).
- `-AuditLevel`: `Basic` for standard reporting or `Verbose` for deep EDR-like event analysis.

---

## 📦 Output Artifacts

All results are saved in the script's directory, followed by an automatic ZIP bundling and cleanup:

1.  **[Hostname].html**: The primary Inventory and Forensic report.
2.  **StatusLog.html**: The EDR analysis, Command Snapshots, and Integrity report.
3.  **[Hostname]_custody.csv**: Chain of custody log with MD5 hashes of all collected files.
4.  **audit_[Timestamp].jsonl**: Technical log of all script operations and errors.
5.  **Evidence ZIP**: A password-free bundle containing all results and exported registry/file fragments.

---

## 🛡 Security & Integrity
- **No Agent Required**: Zero-footprint after execution and cleanup.
- **Integrity First**: MD5 hashes are generated for every artifact and recorded in the custody log.
- **Self-Cleaning**: Automatically removes temporary collection files after successful ZIP archival to minimize forensic noise on the host.

---
*Developed for forensic professionals requiring rapid, reliable, and visually impactful system telemetry.*
