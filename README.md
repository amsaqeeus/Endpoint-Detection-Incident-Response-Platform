# 🛡️ SentinelIR

### Endpoint Detection & Incident Response Platform

SentinelIR is a **Windows endpoint security monitoring and incident response platform** built with Python.

It continuously collects security-relevant information from the local machine, analyzes the collected evidence using multiple detection rules, correlates alerts into incidents, extracts Indicators of Compromise (IOCs), calculates a threat score, and presents the results through a **Streamlit security dashboard**.

The project is designed as a lightweight **EDR-style security tool** for endpoint monitoring, threat detection, investigation, and incident analysis.

---

## 🚨 Project Overview

Modern endpoints generate a large amount of security-relevant activity:

- Running processes
- Network connections
- Persistence mechanisms
- Windows services
- Scheduled tasks
- Command lines
- Suspicious executables
- Registry persistence
- External network communication

Manually analyzing all of this information is difficult.

SentinelIR automates this process by building an investigation pipeline:

```text
┌───────────────────────────────┐
│        Windows Endpoint       │
│                               │
│ Processes                     │
│ Network Connections           │
│ Services                      │
│ Scheduled Tasks               │
│ Persistence                   │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│         Collectors            │
│                               │
│ Process Collector             │
│ Network Collector             │
│ Persistence Collector         │
│ Service Collector             │
│ Scheduled Task Collector     │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│       Detection Engine        │
│                               │
│ Suspicious Processes          │
│ Parent/Child Relationships    │
│ LOLBins                       │
│ Unsigned Processes            │
│ Suspicious Command Lines      │
│ PowerShell Activity           │
│ Scheduled Tasks               │
│ Persistence                   │
│ Network Behavior              │
│ Services                      │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│       Alert Generation        │
│                               │
│ Severity                      │
│ Confidence                    │
│ MITRE ATT&CK Technique        │
│ Description                   │
│ Evidence                      │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│      Incident Correlation     │
│                               │
│ Group related alerts          │
│ Identify affected processes   │
│ Build incidents               │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│        IOC Extraction         │
│                               │
│ IP Addresses                  │
│ URLs                          │
│ Suspicious Paths              │
│ Commands                      │
│ Registry Indicators           │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│       Threat Scoring          │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│      Streamlit Dashboard      │
│                               │
│ Threat Score                  │
│ Alerts                        │
│ Incidents                     │
│ Timeline                      │
│ MITRE ATT&CK                  │
│ IOC Dashboard                 │
└───────────────────────────────┘
✨ Features
🔍 Endpoint Monitoring

SentinelIR collects information directly from the Windows machine where it is executed.

Process Monitoring

Collects information about running processes including:

Process name
PID
Executable path
User
Process information

This allows the detection engine to identify processes running from suspicious locations or behaving unusually.

🌐 Network Monitoring

SentinelIR collects active network connections using psutil.

Collected information includes:

Local IP
Local port
Remote IP
Remote port
Process
PID
Connection status

Example:

Process: firefox.exe
PID: 6108

Local:
192.168.100.8:52144

Remote:
142.251.36.197:443

Status:
ESTABLISHED

The network detector can identify:

External connections
Suspicious ports
Suspicious processes communicating externally
Public IP addresses

Private/local addresses are filtered from IOC extraction.

🧠 Detection Engine

The detection engine combines multiple specialized detectors.

Current detection modules include:

Suspicious Process Detection
Parent/Child Process Detection
LOLBins Detection
Unsigned Process Detection
Command-Line Detection
PowerShell Detection
Persistence Detection
Network Behavior Detection
Service Detection
Scheduled Task Detection

This modular architecture makes it possible to add new detection rules without rewriting the entire system.

🚨 Alert System

Every detection produces a structured alert.

An alert can contain:

{
    "severity": "HIGH",
    "rule": "Suspicious Process",
    "description": "...",
    "mitre": "T1036",
    "technique": "Masquerading",
    "confidence": 85,
    "process": "example.exe",
    "pid": 1234,
    "path": "C:\\...",
    "recommendation": "..."
}
Severity Levels
Severity	Meaning
🔴 HIGH	Strongly suspicious behavior requiring investigation
🟠 MEDIUM	Potentially suspicious behavior
🟢 LOW	Low-confidence or contextual security event
🎯 MITRE ATT&CK Integration

SentinelIR maps detections to MITRE ATT&CK techniques.

Examples currently used include:

T1036
Masquerading

T1053.005
Scheduled Task/Job: Scheduled Task

T1547.001
Registry Run Keys / Startup Folder

T1071
Application Layer Protocol

This helps analysts understand why an event is suspicious rather than simply seeing a generic alert.

🧩 Incident Correlation

Individual alerts are grouped into incidents.

Instead of treating every alert independently, SentinelIR attempts to identify related activity.

For example:

Suspicious Process
        +
Suspicious Executable Path
        +
Persistence
        +
Scheduled Task
        ↓
     Incident

An incident contains information such as:

Incident ID
Process
PID
Severity
Alert count
Confidence
Related alerts
Recommendations
🕒 Investigation Timeline

SentinelIR builds a timeline from generated alerts.

Example:

18:44:26
│
├── HIGH  Suspicious Process
│         CodeSetup-stable-xxxx.exe
│
├── HIGH  Suspicious Process
│         CodeSetup-stable-xxxx.tmp
│
├── MEDIUM Executable Running From Suspicious Location
│
├── HIGH  Suspicious Scheduled Task
│
└── HIGH  Suspicious Registry Persistence

The timeline helps analysts understand the sequence of detected security events.

🔎 IOC Extraction

SentinelIR automatically extracts Indicators of Compromise from alerts.

Currently supported IOC categories:

🌐 IP Addresses

Public IP addresses associated with detected network activity.

🔗 URLs

URLs found inside relevant alert fields.

📂 Suspicious Paths

Potentially suspicious executable or file paths.

💻 Commands

Suspicious command lines and commands.

🔑 Registry Indicators

Registry persistence-related indicators.

Example:

🌐 IP Addresses

142.251.36.197
104.18.32.47
52.123.243.17
📂 Suspicious Paths

C:\Users\pc\AppData\Local\Temp\...
📊 Threat Score

SentinelIR calculates an overall threat score based on generated alerts.

Example:

Threat Score
      52

The dashboard visually represents the score:

0 ─────────────── 40 ─────────────── 70 ─────────────── 100
      LOW                MEDIUM                HIGH

The score provides a quick overview of the current security state of the endpoint.

🖥️ Security Dashboard

The frontend is built with Streamlit.

The dashboard currently displays:

System monitoring status
Threat score
Process count
Network connection count
Alert count
Incident count
Severity statistics
Alert severity chart
MITRE ATT&CK chart
Incident table
Incident details
Investigation timeline
IOC dashboard
Recent alerts
📈 Dashboard Sections
Threat Overview
Threat Score
35

Processes
273

Connections
96

Alerts
20

Incidents
4
Alert Distribution

The dashboard provides a visual breakdown of:

🔴 High
🟠 Medium
🟢 Low
MITRE ATT&CK

Detected techniques are visualized to help understand the attack surface.

Incident Investigation

Users can select an incident and inspect:

Process
PID
Severity
Alert Count
Confidence

Individual alerts can then be expanded to inspect their evidence.

🧪 Example Detection

During development, SentinelIR detected a process executing from a temporary directory:

CodeSetup-stable-e4c7e7b1d6d060162f4aa7f8225271b67ce1df75.exe

Example alert:

Rule:
Executable Running From Suspicious Location

Process:
CodeSetup-stable-e4c7e7b1d6d060162f4aa7f8225271b67ce1df75.exe

PID:
20168

Description:
Process is executing from a user-writable directory.

Confidence:
85

MITRE:
T1036

Technique:
Masquerading

This demonstrates how SentinelIR combines:

Process information
        +
Executable location
        +
Detection rule
        +
MITRE ATT&CK mapping
        +
Confidence

to generate an actionable security alert.

🏗️ Project Architecture
SentinelIR/
│
├── app.py
│
├── core/
│   ├── investigator.py
│   ├── detection_engine.py
│   └── threat_score.py
│
├── collectors/
│   ├── process_collector.py
│   ├── network_collector.py
│   ├── persistence_collector.py
│   ├── service_collector.py
│   └── task_collector.py
│
├── detectors/
│   ├── suspicious_process.py
│   ├── parent_child_detector.py
│   ├── lolbins_detector.py
│   ├── unsigned_process_detector.py
│   ├── commandline_detector.py
│   ├── powershell_detector.py
│   ├── persistence_detector.py
│   ├── network_detector.py
│   ├── service_detector.py
│   └── task_detector.py
│
├── correlation/
│   └── incident_builder.py
│
├── timeline/
│   └── timeline_builder.py
│
├── ioc/
│   └── extractor.py
│
├── response/
│   └── response_engine.py
│
├── models/
│   └── alert.py
│
├── tests/
│
├── requirements.txt
│
└── README.md
⚙️ Investigation Pipeline

The main investigation workflow is:

def investigate():

    report = {}

    report["processes"] = collect_processes()
    report["connections"] = collect_connections()
    report["persistence"] = collect_persistence()
    report["services"] = collect_services()
    report["scheduled_tasks"] = collect_scheduled_tasks()

    analysis = analyze(report)

    report["alerts"] = analysis["alerts"]
    report["incidents"] = analysis["incidents"]

    report["timeline"] = build_timeline(
        report["alerts"]
    )

    report["iocs"] = extract_iocs(
        report["alerts"]
    )

    report["threat_score"] = (
        analysis["threat_score"]
    )

    return report

The result is a centralized investigation report consumed by the dashboard.

🛠️ Technologies
Backend / Detection
Python
psutil
Windows system utilities
PowerShell
Windows Task Scheduler
Security
MITRE ATT&CK
IOC extraction
Endpoint monitoring
Process analysis
Network analysis
Persistence detection
Incident correlation
Frontend
Streamlit
Pandas
Plotly
📦 Installation
1. Clone the repository
git clone https://github.com/YOUR_USERNAME/SentinelIR.git

cd SentinelIR
2. Create a virtual environment
Windows
python -m venv .venv

Activate it:

.venv\Scripts\activate
3. Install dependencies
pip install -r requirements.txt

If requirements.txt has not been created yet:

pip install psutil streamlit pandas plotly streamlit-autorefresh
▶️ Running SentinelIR

Start the Streamlit dashboard:

streamlit run app.py

Then open the URL displayed by Streamlit, usually:

http://localhost:8501
🧪 Testing the Investigation Engine

You can test the backend independently:

python test_investigator.py

Example output:

================================================================================
SentinelIR Investigation
================================================================================

Processes     : 273
Connections   : 96
Persistence   : 10
Services      : 294

Alerts        : 20
Incidents     : 4

Threat Score
52

================================================================================

You can also test high-severity detections:

python test_high.py
🔐 Windows Permissions

Some Windows security information may require elevated privileges.

For best results, run the terminal or PowerShell as:

Administrator

This can improve access to:

Processes
Network connections
Services
Scheduled tasks
Persistence mechanisms

However, the exact amount of information collected depends on Windows permissions and the security context in which SentinelIR is executed.

⚠️ Important: This Is a Defensive Security Tool

SentinelIR is designed for:

Security research
Endpoint monitoring
Defensive security
Incident response
Cybersecurity education
Malware-analysis labs
Blue-team experimentation

It should only be used on systems that you own or have explicit authorization to monitor.

🧠 Design Philosophy

SentinelIR is designed around a modular security architecture.

Instead of putting all detection logic inside one large script, each component has a specific responsibility:

Collectors
    ↓
Detection
    ↓
Alerts
    ↓
Correlation
    ↓
Incidents
    ↓
IOC Extraction
    ↓
Threat Scoring
    ↓
Visualization

This makes the project easier to:

Maintain
Debug
Extend
Test
Add new detection rules
Add new collectors
Integrate additional security intelligence
🚀 Future Improvements

SentinelIR is currently an evolving project.

Planned improvements include:

🔴 Advanced Detection
Behavioral anomaly detection
Process tree visualization
Better parent-child analysis
DLL injection detection
Credential-access detection
Persistence correlation
More LOLBin detection
More Windows-specific telemetry
🌐 Network Security
DNS monitoring
Domain reputation
IP reputation
Connection history
Network anomaly detection
GeoIP enrichment
Threat intelligence integration
🔎 IOC Intelligence

Potential future integrations:

VirusTotal
AbuseIPDB
URLhaus
AlienVault OTX
MISP
🧠 Advanced Analytics

Future versions could include:

Machine learning-based anomaly detection
Behavioral scoring
Baseline-based detection
Automated incident prioritization
📊 Dashboard

Potential improvements:

Interactive process tree
Real-time event stream
Advanced timeline visualization
Incident investigation workspace
IOC enrichment
MITRE ATT&CK matrix
Detection-rule management
💾 Data Storage

A future version could introduce persistent storage for:

Historical alerts
Previous investigations
IOC history
Incident history
Endpoint telemetry

Possible technologies:

SQLite
PostgreSQL
Elasticsearch
🗺️ Roadmap
[x] Process Collection
[x] Network Collection
[x] Persistence Collection
[x] Service Collection
[x] Scheduled Task Collection

[x] Suspicious Process Detection
[x] Network Detection
[x] Persistence Detection
[x] Scheduled Task Detection
[x] Service Detection
[x] Command-Line Detection
[x] PowerShell Detection

[x] Alert Generation
[x] MITRE ATT&CK Mapping
[x] Incident Correlation
[x] Threat Scoring
[x] Timeline Generation
[x] IOC Extraction

[x] Streamlit Dashboard

[ ] Process Tree Visualization
[ ] Advanced Network Intelligence
[ ] IOC Reputation Enrichment
[ ] Historical Investigation Storage
[ ] Advanced Behavioral Detection
[ ] Machine Learning Detection
[ ] Automated Response
📸 Screenshots

Add your dashboard screenshots here after uploading them to the repository.

Example:

![SentinelIR Dashboard](screenshots/dashboard.png)

Recommended screenshots:

screenshots/
│
├── dashboard.png
├── incidents.png
├── timeline.png
└── iocs.png
🤝 Contributing

Contributions are welcome.

If you want to improve SentinelIR:

Fork the repository
Create a feature branch
git checkout -b feature/new-detector
Implement your changes
Test the project
python test_investigator.py
Commit your changes
git add .
git commit -m "Add new detection rule"
Push the branch
git push origin feature/new-detector
Open a Pull Request
👩‍💻 Author

Asma Belkerrouche

Cybersecurity Engineering Student

Interested in:

Cybersecurity
Network Security
Threat Detection
Incident Response
AI for Cybersecurity
Defensive Security
⭐ Project Status
Status: Active Development 🟢

Version: 0.1.0
Platform: Windows
Language: Python
Interface: Streamlit

SentinelIR is currently a research/educational EDR-style project and is continuously being improved with additional detection capabilities and investigation features.

📄 License

This project is intended for educational, research, and defensive cybersecurity purposes.

If you publish the project publicly, add a specific open-source license such as MIT by creating a LICENSE file in the repository.
