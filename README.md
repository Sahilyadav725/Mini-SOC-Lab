# Mini-SOC-Lab
Enterprise EDR Telemetry Ingestion &amp; SOC Analysis Lab


# 🛡️ Enterprise Mini-SOC Lab: Endpoint Detection, Sysmon Telemetry Ingestion & Threat Analysis

## 📌 Project Overview
This repository documents the implementation of a functional **Security Operations Center (SOC) Lab** designed for Endpoint Detection and Response (EDR) telemetry ingestion, threat detection, and log analysis. 

The lab features a 3-tier virtualized infrastructure capturing high-fidelity **Microsoft Sysmon** telemetry on a Windows 11 endpoint, forwarding logs via the **Wazuh Agent**, and ingesting them into a centralized **Wazuh SIEM Manager & Dashboard** for real-time threat investigation.

---

## 🏗️ Lab Architecture & Infrastructure Specs
```text
+-----------------------+       +-----------------------+
|  Attacker (Kali)      |       | Victim (Windows 11)   |
|  - RAM: 4GB | vCPU: 3 |       | - RAM: 4GB | vCPU: 2  |
|  - Role: Recon        |       | - IP: 192.168.241.132 |
+-----------+-----------+       +-----------+-----------+
            |                               |
            | (Network Attack)              | (Sysmon Logs)
            +---------------+---------------+
                            |
                            v
              +---------------------------+
              | Wazuh SIEM Server         |
              | - RAM: 8GB | vCPU: 4      |
              | - Role: Central Ingestion |
              +---------------------------+
```

### 💻 Virtual Machine Allocations (VMware Workstation)

#### 1. Attacker Node (Kali Linux)
* **RAM:** 4 GB | **Processors:** 3 | **Network:** NAT
<img width="537" height="552" alt="Screenshot 2026-07-22 111555" src="https://github.com/user-attachments/assets/0679ae5a-dbcc-4216-9f3d-8b0511884ee1" />


#### 2. SIEM Node (Wazuh Manager 4.14)
* **RAM:** 8 GB | **Processors:** 4 | **Network:** Bridged
<img width="540" height="574" alt="Screenshot 2026-07-22 111507" src="https://github.com/user-attachments/assets/384b3e8e-cb23-467d-92de-b67ba8abfa1a" />


#### 3. Victim Endpoint (Windows 11 x64)
* **RAM:** 4 GB | **Processors:** 2 | **Network:** NAT
<img width="543" height="531" alt="Screenshot 2026-07-22 150959" src="https://github.com/user-attachments/assets/7c1b85cd-f99f-4323-a617-2528b0d47f48" />


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

## 🛡️ Phase 2: Detection Engineering & Rule Validation

In this phase, custom detection capabilities were engineered inside Wazuh SIEM to detect early-stage adversary behavior on Windows 11 endpoints.

---

### 🎯 Objective
Detect discovery and host reconnaissance commands in real-time using **Sysmon Event ID 1 (Process Creation)** telemetry.

---

### 📜 Custom Detection Rule Configuration
- **Rule ID:** `100002`
- **Severity Level:** `10` (High)
- **Log Source:** Sysmon Event ID 1
- **MITRE ATT&CK Mapping:** 
  - **T1087** (Account Discovery)
  - **T1033** (System Owner/User Discovery)

**File Path:** `/var/ossec/etc/rules/local_rules.xml`

```xml
<!-- Custom Reconnaissance Detection Rule for Sysmon Event ID 1 -->
<rule id="100002" level="10">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(whoami|net\s+localgroup|systeminfo|net\s+user)</field>
  <description>Mini-SOC: Host Reconnaissance Command Executed ($win.eventdata.commandLine)</description>
  <mitre>
    <id>T1087</id>
    <id>T1033</id>
  </mitre>
</rule>
```

🧪 Attack Simulation
​The following host discovery commands were executed on the target endpoint (Win11-Endpoint / 192.168.241.132):

whoami
net localgroup administrators
systeminfo
<img width="836" height="443" alt="image" src="https://github.com/user-attachments/assets/71249c02-95f0-4d87-842a-e5e1633d413d" />


📊 Verification & Proof of Concept (PoC)
​All executed commands were matched against rule 100002, producing 3 high-severity alerts on the Wazuh Dashboard.
​Triggered Rule: 100002
​Target Host: Win11-Endpoint
​Captured Execution Targets: whoami.exe, net.exe, sysinfo.exe

​<img width="975" height="521" alt="image" src="https://github.com/user-attachments/assets/e9ad9cca-c38d-48f9-8ef6-988333a338db" />

<img width="945" height="427" alt="image" src="https://github.com/user-attachments/assets/919f3820-168d-4312-b28b-1d009efb30cc" />


# 🛡️ End-to-End Automated Incident Response & SOC Lab

An automated Security Operations Center (SOC) lab built using **Wazuh SIEM**, **Windows 11**, and **Active Response** to detect, block, and visualize brute-force attacks in real-time.

---

## 📐 Architecture & Workflow

```text
[ Attacker (Kali Linux) ] 
       │ 
       ▼ (RDP / Auth Brute Force - Event 4625)
[ Target (Windows 11 Agent) ] 
       │ 
       ▼ (Audit Log Stream via Wazuh Agent)
[ Wazuh SIEM Manager (Ubuntu) ]
       ├── 1. Rule Engine: Match Event 4625 (Rule 60122)
       ├── 2. Threshold Check: >5 Failures / 60s (Custom Rule 100006)
       ├── 3. Trigger Active Response (IP Null-Routing / Route Block)
       └── 4. OpenSearch Dashboard (Real-time Visual Tracking)
```

🔥 Key Features
​Advanced Event Logging: Configured Windows auditpol local security policy to capture granular authentication events (Logon Failures - Event ID 4625).
​Custom Detection Logic: Created custom XML detection rules in Wazuh to catch frequency-based brute-force attacks (5+ attempts within 60 seconds).
​Automated Active Response: Configured dynamic IP blocking via route null-routing upon detection of Rule 100006.
​Visual SOC Dashboards: Built custom OpenSearch widgets (Metric Cards & Pie Charts) for monitoring total attacks blocked and top attacking IP addresses.

⚙️ Configuration & Implementation
​1. Windows Audit Policy Setup
​Executed the following command on the Windows 11 host to capture logon failure telemetry:
```text
auditpol /set /subcategory:"Logon" /failure:enable
```

2. Custom Wazuh Detection Rules (/var/ossec/etc/rules/local_rules.xml)
​Rule 60122: Base rule capturing raw Windows logon failure (Event 4625).
​Rule 100006: Custom correlation rule triggering when 5+ failures occur within 60 seconds.

<group name="windows, logon_failure, custom_bruteforce,">
  <rule id="100006" level="10" frequency="5" timeframe="60">
    <if_matched_sid>60122</if_matched_sid>
    <description>Custom Detection: Multiple Windows Logon Failures detected from same IP (Brute-Force Attempt)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>

3. Active Response Integration (/var/ossec/etc/ossec.conf)
​Automated mitigation configured to execute route-blocking upon trigger of Rule 100006:

<active-response>
  <command>route-null</command>
  <location>local</location>
  <rules_id>100006</rules_id>
  <timeout>600</timeout>
</active-response>

📊 Dashboard Visualizations
​Attacks Blocked (Metric Card): Displays live count of automated IP block triggers (Filtered by rule.id: 100006).
​Top Attacker IPs (Pie Chart): Aggregates incoming brute-force IP addresses using data.win.eventdata.ipAddress (Filtered by rule.id: 60122).
​Dashboard Preview:
<img width="985" height="601" alt="WhatsApp Image 2026-07-26 at 3 38 13 PM" src="https://github.com/user-attachments/assets/19ea3a7b-ef80-4c6a-a760-8f04f004e217" />
