# Universal Log Framework

A lightweight SIH-ready security log normalization framework that ingests heterogeneous logs, detects their format, parses them, normalizes them into a common canonical schema, enriches them with GeoIP/threat metadata, and exposes both a REST API and a simple dashboard demo.

## Features

- Automatic format detection for syslog, JSON, CEF, LEEF, and key-value logs
- Vendor-agnostic parsing pipeline
- Canonical event schema with nested source/event/network structure
- Lossless metadata preservation for vendor-specific fields
- Local GeoIP enrichment dataset
- Threat intelligence enrichment for suspicious IPs
- Validation before storage or forwarding
- FastAPI ingestion and event feed endpoints
- Simple dashboard for live demonstration
- Docker support for platform-independent deployment

## Architecture

The project follows the SIH architecture:

1. Collect logs from files, syslog, or API payloads
2. Detect the incoming format
3. Parse into structured event data
4. Normalize to a universal schema
5. Enrich with GeoIP and reputation metadata
6. Validate and persist/send the event
7. Expose dashboard and API views

## Project structure

```text
universal-log-framework/
├── app/
│   ├── collector/
│   ├── detector/
│   ├── parser/
│   ├── normalizer/
│   ├── enrichment/
│   ├── validator/
│   ├── models/
│   └── main.py
├── tests/
├── sample_logs/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
└── pytest.ini
```

## Quick start

```bash
cd universal-log-framework
python -m pytest
python -m uvicorn app.main:app --reload
```

Then open:

- http://localhost:8000/docs
- http://localhost:8000/dashboard
- http://localhost:8000/events

## Example log ingestion

```bash
curl -X POST http://localhost:8000/logs \
  -H "Content-Type: application/json" \
  -d '{"log":"src=10.0.0.5 dst=8.8.8.8 action=deny"}'
```

## Docker

```bash
docker compose up --build
```

## Sample logs

The repository includes example files under `sample_logs/` for testing and demonstration.
