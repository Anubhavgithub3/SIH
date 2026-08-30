# Universal Log Framework

A modular cybersecurity log processing platform designed to ingest heterogeneous security logs, detect their format, normalize them into a common schema, enrich them with contextual intelligence, and visualize the results through a responsive dashboard and REST API.

## Overview

Modern enterprise and security environments generate logs from multiple devices and software systems, including firewalls, Linux servers, application gateways, IDS/IPS systems, VPN appliances, and cloud services. These logs vary widely in structure, syntax, and field naming conventions, which complicates centralized monitoring and threat analysis.

This project addresses that challenge by building a vendor-agnostic log normalization and enrichment framework. It can accept raw logs from files or API payloads, detect the log format automatically, parse the fields, map them into a canonical event format, enrich the event with threat and geographic context, validate the result, and expose it through APIs and a dashboard.

The solution is designed to be lightweight, modular, and demo-ready for SIH, cybersecurity innovation, and security operations use cases.

## Problem Statement

Security teams typically collect logs from many different sources, each producing unique schemas. Without a common normalization layer:

- correlation across logs becomes difficult,
- detection logic is harder to maintain,
- incident triage is slow,
- valuable context such as IP reputation and geography is often lost,
- analysts must manually interpret inconsistent data formats.

The Universal Log Framework solves this by standardizing raw security telemetry into one consistent format that is easier to query, analyze, and visualize.

## Key Features

- Automatic detection of multiple log formats
  - Syslog
  - JSON
  - CEF
  - LEEF
  - Key-value logs
- Structured parsing of vendor-specific security events
- Canonical normalization to a common schema
- Support for nested event structures such as:
  - source
  - event
  - network
  - enrichment
  - threat
- GeoIP enrichment for country and location mapping
- Threat intelligence enrichment for suspicious or malicious IPs
- Validation before storing or forwarding events
- FastAPI-based REST API
- Live dashboard for monitoring and demo purposes
- Lightweight machine learning anomaly scoring layer for risk classification
- Docker support for easy deployment
- Test suite for regression validation

## Use Cases

- SOC monitoring dashboards
- Security event aggregation from heterogeneous sources
- Threat investigation and forensic analysis
- Log normalization before SIEM integration
- Research and mock deployment for cybersecurity innovation projects
- Educational demonstration of log ingestion and parsing pipelines

## Technology Stack

- Python 3
- FastAPI
- Uvicorn
- scikit-learn
- Pytest
- Docker
- HTML/CSS/JavaScript dashboard layer

## System Architecture

The project follows a modular, pipeline-based architecture:

1. Log Collection
   - Reads log files from disk
   - Accepts API payloads
   - Processes raw or semi-structured input

2. Format Detection
   - Identifies whether the log is JSON, syslog, CEF, LEEF, or key-value based

3. Parsing
   - Extracts meaningful fields into structured Python dictionaries

4. Normalization
   - Maps fields into a universal event schema
   - Preserves raw metadata when needed

5. Enrichment
   - Adds GeoIP metadata
   - Adds threat reputation context
   - Adds risk-oriented intelligence

6. Validation
   - Rejects malformed or unusable records
   - Keeps a valid, standardized dataset

7. Output & Visualization
   - Exposes events through APIs
   - Powers the live dashboard
   - Supports downstream analytics and integration

## Project Structure

```text
universal-log-framework/
├── app/
│   ├── collector/
│   ├── detector/
│   ├── parser/
│   ├── normalizer/
│   ├── enrichment/
│   ├── validator/
│   ├── ml/
│   ├── main.py
│   └── __init__.py
├── tests/
│   └── test_pipeline.py
├── sample_logs/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
├── SIH_DEMO_SCRIPT.md
├── pytest.ini
└── .gitignore
```

## Installation

### 1. Clone the project

```bash
git clone <repository-url>
cd universal-log-framework
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Project

### Start the application

```bash
uvicorn app.main:app --reload
```

The service will be available at:

- http://localhost:8000
- http://localhost:8000/dashboard
- http://localhost:8000/docs
- http://localhost:8000/events

## Testing

Run the test suite using:

```bash
pytest -q
```

The repository contains automated checks for:

- format detection
- parser accuracy
- event normalization
- API ingestion
- dashboard endpoints
- health and summary APIs
- ML anomaly score output

## Example API Requests

### Ingest a log payload

```bash
curl -X POST http://localhost:8000/logs \
  -H "Content-Type: application/json" \
  -d '{"log":"src=10.0.0.5 dst=8.8.8.8 action=deny"}'
```

### Get all events

```bash
curl http://localhost:8000/events
```

### Get health status

```bash
curl http://localhost:8000/health
```

### Get security summary

```bash
curl http://localhost:8000/summary
```

### Get ML anomaly insights

```bash
curl http://localhost:8000/api/ml/insights
```

## Sample Normalized Event Structure

```json
{
  "source": "firewall",
  "event": {
    "action": "deny",
    "severity": "high",
    "type": "firewall_event"
  },
  "network": {
    "source_ip": "10.0.0.5",
    "destination_ip": "8.8.8.8"
  },
  "enrichment": {
    "country": "IN"
  },
  "threat": {
    "reputation": "suspicious"
  }
}
```

## Machine Learning Component

The project includes a lightweight anomaly detection module under the `app/ml` package. It evaluates each event based on features such as:

- severity level,
- deny/block action,
- repeated authentication failures,
- suspicious IP reputation,
- risky geography,
- suspicious keywords in the message.

This model helps infer whether a log event behaves like benign traffic or suspicious behavior and contributes to the security dashboard's risk posture.

## Docker Deployment

Build and run with Docker:

```bash
docker compose up --build
```

This is helpful for demonstrating the application in a clean environment or deploying the service to a test platform.

## How the Project Helps Security Operations

This framework helps reduce the operational burden of dealing with heterogeneous security logs by:

- centralizing log parsing,
- standardizing event schemas,
- improving status visibility,
- enabling faster investigation,
- enriching events with threat context,
- making the platform suitable for future SIEM integration.

## Future Enhancements

- Real-time streaming ingestion
- Database-backed persistent storage
- Advanced ML models for anomaly detection and classification
- Alert correlation engine
- Role-based access to dashboard views
- Integration with external SIEM tools
- Event retention and historical analytics

## Conclusion

The Universal Log Framework is a practical cybersecurity solution that demonstrates how raw, varied log data can be transformed into normalized, enriched, and actionable intelligence. It is built to showcase security operations automation, log intelligence, and machine-assisted threat detection in a compact and scalable architecture.

## License

This project is intended for educational and demonstration purposes in cybersecurity and SIH-style problem solving.
