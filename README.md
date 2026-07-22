# Mini-SOC-Lab
Enterprise EDR Telemetry Ingestion &amp; SOC Analysis Lab


# 🛡️ Enterprise Mini-SOC Lab: Endpoint Detection, Sysmon Telemetry Ingestion & Threat Analysis

## 📌 Project Overview
This repository documents the implementation of a functional **Security Operations Center (SOC) Lab** designed for Endpoint Detection and Response (EDR) telemetry ingestion, threat detection, and log analysis. 

The lab features a 3-tier virtualized infrastructure capturing high-fidelity **Microsoft Sysmon** telemetry on a Windows 11 endpoint, forwarding logs via the **Wazuh Agent**, and ingesting them into a centralized **Wazuh SIEM Manager & Dashboard** for real-time threat investigation.

---

## 🏗️ Lab Architecture & Infrastructure Specs

+------------------------------------+          +-----------------------------------+
|      Attacker (Kali Linux)         |          |    Victim Endpoint (Win11)        |
|  - RAM: 4 GB | vCPU: 3             |          |  - RAM: 4 GB | vCPU: 2            |
|  - Role: Reconnaissance & Attacks  |          |  - Agent: Win11-Endpoint (ID 001) |
+-----------------+------------------+          |  - IP: 192.168.241.132            |
|                             +-----------------+-----------------+
|                                               |
+-----------------------+-----------------------+
|
v (Sysmon Event Stream)
+-----------------------------------+
|    Wazuh SIEM Manager & Indexer   |
|  - RAM: 8 GB | vCPU: 4            |
|  - Role: Ingestion & Dashboards   |
+-----------------------------------+

### 💻 Virtual Machine Allocations (VMware Workstation)

#### 1. Attacker Node (Kali Linux)
* **RAM:** 4 GB | **Processors:** 3 | **Network:** NAT
<img width="537" height="552" alt="Screenshot 2026-07-22 111555" src="https://github.com/user-attachments/assets/0679ae5a-dbcc-4216-9f3d-8b0511884ee1" />


#### 2. SIEM Node (Wazuh Manager 4.14)
* **RAM:** 8 GB | **Processors:** 4 | **Network:** Bridged
<img width="540" height="574" alt="Screenshot 2026-07-22 111507" src="https://github.com/user-attachments/assets/384b3e8e-cb23-467d-92de-b67ba8abfa1a" />


#### 3. Victim Endpoint (Windows 11 x64)
* **RAM:** 4 GB | **Processors:** 2 | **Network:** NAT


---

## ⚙️ Telemetry Pipeline Setup

1. **Sysmon Deployment:** Installed **Microsoft System Monitor (Sysmon)** on the Windows 11 machine integrated with **SwiftOnSecurity** (`sysmonconfig-export.xml`) configuration to filter noise and capture high-fidelity process executions, network connections, and file modifications.
2. **Wazuh Agent Integration:** Configured the `Win11-Endpoint` agent (`agent.id: 001`, `agent.ip: 192.168.241.132`) to forward `Microsoft-Windows-Sysmon/Operational` event logs directly to the Wazuh Manager.
3. **Pipeline Ingestion Test:** Verified log streaming and parsing via the OpenSearch/Wazuh Indexer backend.

---

## 🧪 Threat Simulation & Detection Verification

### 1. Adversary Reconnaissance Simulation (Host Level)
Simulated adversary execution of Living-off-the-Land (LotL) discovery commands inside Windows PowerShell:
```powershell
whoami /priv
net localgroup administrators
```

<img width="837" height="401" alt="WhatsApp Image 2026-07-22 at 3 34 05 PM" src="https://github.com/user-attachments/assets/042450e3-657c-4231-93d8-87ddccd7aea5" />'''

SIEM Telemetry & Log Analysis
​Inside the Wazuh Dashboard (Discover Module), applied DQL filtering to isolate Sysmon Process Creation events:
```powershell
data.win.system.eventID: "1"
```

Ingested Hits: 55+ execution hits successfully indexed in the time histogram.
​
<img width="982" height="597" alt="WhatsApp Image 2026-07-22 at 3 43 33 PM" src="https://github.com/user-attachments/assets/8448fa3d-6ed4-447f-ae05-0aaeef36ea2f" />

​Captured Event Artifacts & Field Parsing:
```
Agent Identifier: agent.name: Win11-Endpoint | agent.ip: 192.168.241.132
```
​Executed Process Path:
```
C:\Windows\System32\net.exe and C:\Windows\SysWOW64\net.exe
```
​Original File Name:
```
net.exe
```
​Process Tracking:
```
data.win.eventdata.parentProcessGuid
```
tracked for process parent-child relation.
​
<img width="927" height="427" alt="WhatsApp Image 2026-07-22 at 3 45 18 PM" src="https://github.com/user-attachments/assets/da172a72-41de-4fd9-a232-90aa48d113b1" />

​🛠️ System Reliability & Troubleshooting Log
​Issue Identified: Wazuh Indexer service failure leading to API connection refusal and authentication errors.
​Root Cause: Java process memory starvation leading to Linux Kernel Out-Of-Memory (oom-kill) process termination.
​Resolution Steps:
​Expanded Virtual Machine memory allocation to 8 GB RAM and 4 vCPUs.
​Corrected command-line syntax errors for configuration parsing (cat /etc/wazuh-indexer/wazuh-passwords.txt).
​Restarted core services (wazuh-manager) and verified cluster readiness.


Key Takeaways & Skills Demonstrated
​EDR Engineering: Configuring Sysmon schema for noise reduction and high-fidelity event generation.
​SIEM Operations: Setting up agent-manager telemetry pipelines and performing DQL query analysis in OpenSearch.
​Host Incident Response: Identifying process creation metadata (Event ID 1) for post-exploitation discovery detection.
​Infrastructure Engineering: Allocating and troubleshooting virtualized SOC compute and memory requirements under heavy indexing loads.
