import json
from datetime import datetime


def create_payload(filename, filetype, salt, encrypted_data, integrity=None):

    payload = {
        "version": "HFV2",
        "filename": filename,
        "filetype": filetype,
        "salt": salt,
        "encrypted_data": encrypted_data,
        "integrity": integrity,
        "created_at": datetime.utcnow().isoformat()
    }

    return json.dumps(payload)


def parse_payload(payload_str):
    try:
        return json.loads(payload_str)
    except Exception:
        raise Exception("Invalid JSON payload")

def validate_payload(payload):
    required = ["version", "filename", "filetype", "salt", "encrypted_data"]

    if payload.get("version") not in ["HFV2"]:
        return False

    return all(k in payload for k in required)