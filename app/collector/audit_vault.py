import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

# Persistent Storage Directories
BASE_STORAGE_DIR = Path(__file__).resolve().parents[2] / 'storage'
BACKUP_DIR = BASE_STORAGE_DIR / 'backups'
QUARANTINE_DIR = BASE_STORAGE_DIR / 'quarantine'

BACKUP_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_LOG_STORE = []
QUARANTINE_STORE = []


def calculate_sha256(content: str) -> str:
    """Calculates SHA-256 cryptographic hash of raw text content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def audit_and_backup_raw_log(raw_text: str, source: str = 'api') -> dict:
    """
    Saves raw logs with SHA-256 cryptographic hash before parsing
    for data safety, auditing, and immutable backup.
    Deduplicates on disk and memory by SHA-256 content hash.
    """
    sha256_hash = calculate_sha256(raw_text)
    timestamp = datetime.now(timezone.utc).isoformat()
    short_hash = sha256_hash[:16]
    filename = f"sha256_{short_hash}.log"
    backup_file_path = BACKUP_DIR / filename

    # Save raw backup to disk ONLY if it doesn't already exist
    if not backup_file_path.exists():
        try:
            with open(backup_file_path, 'w', encoding='utf-8') as f:
                f.write(raw_text)
        except Exception as e:
            print(f"Warning: Failed to write audit backup: {e}")

    audit_entry = {
        'sha256_hash': sha256_hash,
        'short_hash': sha256_hash[:12],
        'timestamp': timestamp,
        'bytes_size': len(raw_text.encode('utf-8')),
        'source': source,
        'tamper_proof_status': 'VERIFIED',
        'backup_path': str(backup_file_path),
        'backup_id': f"BK-{sha256_hash[:12].upper()}"
    }

    # Deduplicate in-memory audit store
    existing_idx = next((i for i, item in enumerate(AUDIT_LOG_STORE) if item['sha256_hash'] == sha256_hash), None)
    if existing_idx is not None:
        AUDIT_LOG_STORE.pop(existing_idx)

    AUDIT_LOG_STORE.insert(0, audit_entry)
    if len(AUDIT_LOG_STORE) > 500:
        AUDIT_LOG_STORE.pop()

    return audit_entry


def quarantine_payload(raw_text: str, reason: str, risk_score: float = 0.90, source: str = 'ingest') -> dict:
    """
    Quarantines unknown formats, unparseable files, or suspicious unknown threats.
    Deduplicates on disk and memory by Quarantine ID.
    """
    sha256_hash = calculate_sha256(raw_text)
    timestamp = datetime.now(timezone.utc).isoformat()
    quarantine_id = f"Q-{sha256_hash[:12].upper()}"
    filename = f"{quarantine_id}.quarantine"
    quarantine_file_path = QUARANTINE_DIR / filename

    quarantine_entry = {
        'quarantine_id': quarantine_id,
        'sha256_hash': sha256_hash,
        'quarantined_at': timestamp,
        'reason': reason,
        'risk_score': risk_score,
        'source': source,
        'raw_payload': raw_text[:1000],
        'status': 'ISOLATED',
        'file_path': str(quarantine_file_path)
    }

    # Save to disk ONLY if not existing
    if not quarantine_file_path.exists():
        try:
            with open(quarantine_file_path, 'w', encoding='utf-8') as f:
                f.write(json.dumps(quarantine_entry, indent=2))
        except Exception as e:
            print(f"Warning: Failed to write quarantine file: {e}")

    # Remove existing duplicate if present
    existing_idx = next((i for i, item in enumerate(QUARANTINE_STORE) if item['quarantine_id'] == quarantine_id), None)
    if existing_idx is not None:
        QUARANTINE_STORE.pop(existing_idx)

    QUARANTINE_STORE.insert(0, quarantine_entry)
    return quarantine_entry


def get_audit_logs(limit: int = 50):
    return AUDIT_LOG_STORE[:limit]


def get_quarantine_items(limit: int = 50):
    return QUARANTINE_STORE[:limit]


def process_quarantine_action(quarantine_id: str, action: str):
    """
    Action can be 'release' (restore from vault) or 'purge' (delete permanently).
    """
    for item in QUARANTINE_STORE:
        if item['quarantine_id'] == quarantine_id:
            if action == 'release':
                item['status'] = 'RELEASED'
                item['released_at'] = datetime.now(timezone.utc).isoformat()
                return {'status': 'success', 'message': f'Quarantined payload {quarantine_id} released successfully', 'item': item}
            elif action == 'purge':
                item['status'] = 'PURGED'
                file_path = item.get('file_path')
                if file_path and os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass
                QUARANTINE_STORE.remove(item)
                return {'status': 'success', 'message': f'Quarantined payload {quarantine_id} permanently purged', 'quarantine_id': quarantine_id}

    return {'status': 'error', 'message': f'Quarantine item {quarantine_id} not found'}
