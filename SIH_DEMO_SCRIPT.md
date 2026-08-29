# SIH Demo Script: Universal Log Framework

## 1. Problem Statement

Modern cybersecurity systems receive logs from many sources: Linux servers, firewalls, routers, IDS/IPS devices, VPN gateways, and cloud services. These logs use different formats, fields, and structures, which makes centralized analysis difficult.

Our project solves this by converting all heterogeneous logs into one common, normalized event schema.

## 2. Project Objective

We build a universal log framework that:
- detects the format automatically,
- parses different log types,
- normalizes them into a common schema,
- preserves vendor-specific metadata,
- enriches events with GeoIP and reputation data,
- validates events before forwarding them,
- exposes the processed events through a simple dashboard and API.

## 3. Solution Overview

The framework consists of four main stages:

1. Ingestion
   - File logs
   - Syslog input
   - REST API payloads

2. Detection and Parsing
   - JSON
   - Syslog
   - CEF
   - Key-value logs

3. Normalization
   - Converts all fields into a common structure such as:
     - network.source_ip
     - network.destination_ip
     - event.action
     - event.severity

4. Enrichment and Validation
   - GeoIP lookup
   - Threat intelligence lookup
   - Validation before storing/sending

## 4. Demonstration Flow

### Step 1: Show multiple log formats

From sample logs, show examples such as:
- Linux syslog line
- JSON alert
- key-value firewall log
- CEF security event
python -m app.main sample_logs/sample.json/Users/anubhavkumar/sih/.venv/bin/python -m app.main sample_logs/sample.json
### Step 2: Send input through the API

Use the REST endpoint:

```bash
curl -X POST http://localhost:8000/logs \
  -H "Content-Type: application/json" \
  -d '{"log":"src=10.0.0.5 dst=8.8.8.8 action=deny"}'
```

### Step 3: Explain automatic detection

Point out that the framework automatically recognizes the log type and chooses the relevant parser.

### Step 4: Show normalized event output

Example output:

```json
{
  "source": "api",
  "event": {
    "action": "deny",
    "severity": "INFO",
    "type": "unknown"
  },
  "network": {
    "source_ip": "10.0.0.5",
    "destination_ip": "8.8.8.8"
  },
  "enrichment": {
    "country": "IN",
    "geo": {
      "country": "IN",
      "city": "Bengaluru"
    }
  },
  "threat": {
    "reputation": "unknown"
  }
}
```

### Step 5: Show dashboard

Open the dashboard at:

```text
http://localhost:8000/dashboard
```

Explain that it gives a quick visual summary of processed events, threats, and recent activity.

### Step 6: Show event feed

Open:

```text
http://localhost:8000/events
```

This demonstrates the log stream being stored in memory and delivered for downstream analytics.

## 5. Why this is strong for SIH

This project highlights:
- heterogenous data handling,
- standardization via normalization,
- security relevance,
- scalability through modular design,
- practical deployment as a containerized application.

## 6. Final Pitch

> We built a universal log processing framework for cyber security data that automatically ingests, detects, parses, normalizes, enriches, validates, and visualizes logs from different devices and formats into one consistent schema for advanced analysis.

## 7. Suggested closing line

> This solution reduces the complexity of handling different security logs and makes the data ready for SIEM, threat detection, and analytics systems.
