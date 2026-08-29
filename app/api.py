from fastapi import FastAPI

from app.detector.format_detector import detect_format
from app.main import process_log_payload

app = FastAPI(title='Universal Log Framework')


@app.post('/logs')
def ingest_log(payload: dict):
    raw_log = payload.get('log') or payload.get('message') or ''
    if not raw_log:
        return {'error': 'No log payload provided'}
    return process_log_payload(raw_log)
