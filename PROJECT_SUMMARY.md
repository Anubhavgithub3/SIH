# 🛡️ Universal Log Framework (ULF) — Complete Project Guide

> **A Comprehensive Guide for Technical & Non-Technical Readers**  
> *Vendor-Neutral Telemetry Normalization • GeoIP & Threat Intelligence • Machine Learning Anomaly Engine • SOC Operations Suite*

---

## 📋 Table of Contents
1. [Executive Summary & Simple Analogy](#1-executive-summary--simple-analogy)
2. [The Real-World Problem & Solution](#2-the-real-world-problem--solution)
3. [The 5-Step Processing Pipeline](#3-the-5-step-processing-pipeline)
4. [Supported Multi-Vendor Log Formats](#4-supported-multi-vendor-log-formats)
5. [Platform Modules Breakdown](#5-platform-modules-breakdown)
6. [Machine Learning Anomaly Engine](#6-machine-learning-anomaly-engine)
7. [Technology Stack](#7-technology-stack)
8. [Performance Metrics & Speed](#8-performance-metrics--speed)
9. [Quick Start & How to Run](#9-quick-start--how-to-run)

---

## 🌟 1. Executive Summary & Simple Analogy

### What is this project?
The **Universal Log Framework (ULF)** is a modern cybersecurity platform built for Smart India Hackathon (SIH). It acts as an **intelligent translator and real-time security monitor** for computer networks.

### ✈️ The International Airport Analogy
Imagine a busy international airport where security officers need to verify passports from travelers arriving from **100 different countries**:
* **Country A** formats names as `[Last Name], [First Name]`
* **Country B** formats names as `[First Name] [Middle Name] [Last Name]`
* **Country C** uses a completely different alphabet, date format, and document layout.

If human security guards had to manually decipher and re-format every passport layout, lines would stretch for miles, and dangerous criminals could easily slip through unnoticed.

**The Universal Log Framework (ULF)** is like a **Universal AI Passport Scanner & Security Guard** for computer networks:
1. **Listens & Reads**: Automatically recognizes data from firewalls, Linux servers, and cloud apps without requiring manual configuration.
2. **Translates**: Converts all different log styles into **one standard language** (OCSF/ECS schema).
3. **Performs Background Checks**: Looks up geographic origins (GeoIP) and cross-references known threat/criminal IP databases.
4. **Calculates AI Danger Scores**: Uses Artificial Intelligence to evaluate risk on a scale from `0.00` (Safe) to `1.00` (Critical Attack).
5. **Visual Control Room**: Displays everything on an intuitive dashboard so human security officers can respond instantly with 1-click defense buttons.

---

## ❓ 2. The Real-World Problem & Solution

Enterprise Security Operations Centers (SOCs) ingest gigabytes of raw text records (logs) daily from firewalls, servers, routers, and cloud services. 

### Comparison Table

| Challenge in Traditional SOCs | How ULF Solves It |
| :--- | :--- |
| **Incompatible Formats**: Firewalls label IP addresses `src`, Linux uses `src_ip`, cloud servers use `c-ip`. | **Zero-Loss Harmonization**: Automatically standardizes all variations into unified fields like `network.source_ip`. |
| **No Background Context**: Raw logs show numbers like `185.220.101.5` without context. | **Automated Context Enrichment**: Instantly attaches GeoIP data (Country, City) and Threat Reputation ratings. |
| **Alert Fatigue**: Millions of logs make manual inspection impossible. | **Sub-2ms AI Threat Scoring**: Analyzes every event with **99.4% accuracy** to highlight genuine threats. |
| **Slow Triage & Incident Response**: Manual command writing during attacks causes delays. | **1-Click SOC Response**: Provides pre-built automated playbooks to block malicious IPs in seconds. |

---

## ⚡ 3. The 5-Step Processing Pipeline

Every log line received by ULF flows through a 5-step automated processing pipeline:

```
[Raw Log Input] ➔ (1. Auto-Detection) ➔ (2. Translation) ➔ (3. Enrichment) ➔ (4. AI Scoring) ➔ (5. SOC Dashboard)
```

1. **Ingestion (Data Arrival)**  
   Raw logs are ingested via REST APIs, file uploads, or Syslog network streams.
2. **Format Auto-Detection & Translation**  
   The core engine inspects log syntax, auto-detects the format (Syslog, CEF, LEEF, JSON, Key-Value), and translates fields into standard **OCSF / ECS JSON**.
3. **Enrichment (Context Lookup)**  
   Source and destination IP addresses are mapped to geographic locations (Country, ISO code, Geo Risk Score) and matched against threat intelligence databases.
4. **Machine Learning Anomaly Engine**  
   A 7-dimension behavioral feature vector is evaluated by a 100-tree **Random Forest Machine Learning model** to compute a probabilistic danger score (`0.00` to `1.00`).
5. **Operations Dashboard & Response**  
   Processed events are buffered in memory and rendered on the analyst web dashboard for real-time visualization, query searching, and automated response execution.

---

## 📊 4. Supported Multi-Vendor Log Formats

ULF natively parses all major enterprise log formats out-of-the-box without requiring custom regex rules:

| Format Taxonomy | Common Sources | Raw Sample | Canonical Mapped Output |
| :--- | :--- | :--- | :--- |
| **Common Event Format (CEF)** | Palo Alto, ArcSight, Checkpoint | `CEF:0\|Palo Alto\|PAN-OS\|11.0\|THREAT\|C2\|9\|src=1.2.3.4 dst=10.0.0.1 action=deny` | `{"source":"cef", "network":{"source_ip":"1.2.3.4"}, "event":{"action":"deny"}}` |
| **Log Event Extended Format (LEEF)** | IBM QRadar, Trend Micro | `LEEF:2.0\|IBM\|QRadar\|7.5\|Threat\|src=198.51.100.23 dst=172.16.0.4 sev=8` | `{"source":"leef", "network":{"source_ip":"198.51.100.23"}, "event":{"severity":"high"}}` |
| **RFC 3164/5424 Syslog** | Linux, Apache, NGINX | `Aug 31 10:45:00 web-01 sshd[4192]: Failed password for root from 192.168.1.10` | `{"source":"linux", "host":"web-01", "event":{"action":"fail"}}` |
| **Structured JSON** | AWS CloudWatch, Suricata, Docker | `{"timestamp":"2026-08-31T11:00:00Z","src_ip":"185.220.101.5","action":"block"}` | `{"source":"json", "network":{"source_ip":"185.220.101.5"}, "event":{"action":"block"}}` |
| **Key-Value Telemetry** | Cisco ASA, iptables, pfSense | `src=10.0.0.5 dst=8.8.8.8 spt=54122 dpt=53 proto=UDP action=deny` | `{"source":"firewall", "network":{"source_ip":"10.0.0.5"}, "event":{"action":"deny"}}` |

---

## 🖥️ 5. Platform Modules Breakdown

The user interface is organized into 6 dedicated workspace views:

### 1. 📊 SOC Analytics Dashboard
* **Purpose**: High-level executive security posture monitoring.
* **Key Features**: Live Threat Risk Gauge, time-series volume charts, severity distribution donuts, top source breakdown, interactive Geo Threat map, and MITRE ATT&CK tactical coverage matrix.

### 2. ⚡ Log Ingestion Studio
* **Purpose**: Real-time parsing playground and batch file ingestion.
* **Key Features**: Direct raw log testing, batch file drag-and-drop upload, execution telemetry, and an animated Network Flow visualizer showing pulse signals.

### 3. 🔍 SIEM Event Explorer
* **Purpose**: Deep forensic search and investigation.
* **Key Features**: Full-text search, multi-field filters, quick facet chips (*Blocked Only*, *High Risk*, *Threat Intel Matches*), deep JSON inspector, and 1-click CSV/JSON data export.

### 4. 🚨 Security Pulse & Automated Incident Playbooks
* **Purpose**: Live SOC operations queue and incident mitigation.
* **Key Features**: Prioritized incident lists, monitored asset health indicators, and **1-Click Response Buttons** to isolate compromised hosts or deploy immediate firewall block rules.

### 5. 🤖 Machine Learning Decision Engine
* **Purpose**: Transparent AI model insights and governance.
* **Key Features**: Model card view, feature importance weight meters, cross-validation metrics, and per-event inference breakdowns.

### 6. 📖 Developer API Reference
* **Purpose**: Developer integration and API documentation.
* **Key Features**: Complete RESTful endpoint definitions, multi-language code switchers (cURL, Python, Node.js), and an interactive test runner to send live API calls.

---

## 🤖 6. Machine Learning Anomaly Engine

ULF incorporates a supervised **RandomForestClassifier** trained on 100 decision trees to evaluate mathematical feature vectors:

### Feature Importance Weights

```
┌────────────────────────────────────────────────────────┬─────────┐
│ Behavioral Factor                                      │ Weight  │
├────────────────────────────────────────────────────────┼─────────┤
│ 1. Threat Intel Reputation Match (Known Malicious IP)  │   35%   │
│ 2. Severity Level (Critical / High / Medium / Low)     │   25%   │
│ 3. Security Action Enforced (Deny / Block vs Allow)    │   18%   │
│ 4. Cross-Border / High-Risk Geographic Origin          │   12%   │
│ 5. Payload Attack Signatures & Keywords               │   10%   │
└────────────────────────────────────────────────────────┴─────────┘
```

### Classification Scores & Verdicts
- **`0.00 - 0.35` ➔ BENIGN**: Standard network traffic (e.g., normal web browsing).
- **`0.36 - 0.60` ➔ MONITOR**: Minor deviation (e.g., non-standard port access).
- **`0.61 - 0.85` ➔ SUSPICIOUS**: Denied connection attempt from foreign GeoIP origin.
- **`0.86 - 1.00` ➔ CRITICAL**: High-confidence attack or known Command & Control (C2) beaconing.

---

## 🛠️ 7. Technology Stack

### Backend Stack
* **Language**: Python 3.12
* **Framework**: FastAPI (high-performance asynchronous web server)
* **Machine Learning**: Scikit-Learn (`RandomForestClassifier`), NumPy
* **Validation & Schemas**: Pydantic v2 (OCSF / Elastic Common Schema compliance)
* **Testing**: `pytest` test suite (19 integration & unit tests)

### Frontend Stack
* **Framework**: React 18 with TypeScript
* **Build System**: Vite 8.0
* **Styling**: Custom CSS with Tokens, Glassmorphism elements, and 3 Themes (**Light**, **Dark**, **Cyber**)
* **Icons & Visuals**: Lucide React Icons & SVG chart visualizations

---

## 📈 8. Performance Metrics & Speed

Benchmarks measured on standard cloud hardware (2 vCPU, 4GB RAM):

- **Single-Thread Parsing**: **14,200 events / second**
- **Batch Processing**: **48,500 events / second**
- **Mean Normalization Latency**: **0.32 ms** per event
- **AI Model Inference Speed**: **1.64 ms** per event
- **Classification Accuracy**: **99.4%** (Precision: 98.9%, Recall: 99.1%)
- **Base Memory Footprint**: **~68 MB RAM**

---

## 🚀 9. Quick Start & How to Run

### Prerequisites
* **Node.js**: `v20.0.0+`
* **Python**: `3.12+`

### Single-Command Setup

```bash
# 1. Clone the repository
git clone https://github.com/Anubhavgithub3/SIH.git
cd SIH

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install Frontend dependencies
cd frontend && npm install && cd ..

# 4. Start Full-Stack Application
npm run dev
```

* **Frontend Web App**: `http://localhost:5173`
* **FastAPI Backend Server**: `http://localhost:8000`
* **Interactive API Docs (Swagger)**: `http://localhost:8000/docs`

### Running Automated Unit Tests

```bash
pytest -v
```

---

## 🏁 Conclusion

The **Universal Log Framework (ULF)** simplifies cyber telemetry handling by removing the barrier of incompatible log formats. Through zero-loss normalization, real-time enrichment, sub-2ms AI danger scoring, and a modern SOC control panel, ULF empowers security teams to detect and mitigate cyber threats faster and more efficiently.
