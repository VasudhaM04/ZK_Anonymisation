import hmac
import hashlib
import os
import uuid
import json
import base64
from datetime import datetime, timezone, timedelta

# 🔐 Keys from environment
SECRET_SALT = os.environ.get("SECRET_SALT", "dev_secret").encode()
OPERATOR_SALT = os.environ.get("OPERATOR_SALT", "dev_op").encode()
QR_SIGNING_KEY = os.environ.get("QR_SIGNING_KEY", "dev_qr").encode()

# ─────────────────────────────────────────────
# Utils
# ─────────────────────────────────────────────
def normalize(value: str) -> str:
    return value.strip().lower()

def _hmac(key, value):
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()

# ─────────────────────────────────────────────
# Operator Commitment
# ─────────────────────────────────────────────
def make_operator_commitment(operator_id: str):
    return _hmac(OPERATOR_SALT, normalize(operator_id))

def verify_operator(candidate, stored):
    return hmac.compare_digest(
        make_operator_commitment(candidate),
        stored
    )

# ─────────────────────────────────────────────
# Session
# ─────────────────────────────────────────────
def create_session(operator_id):
    now = datetime.now(timezone.utc)

    return {
        "session_id": str(uuid.uuid4()),
        "op_commitment": make_operator_commitment(operator_id),
        "expires_at": (now + timedelta(hours=8)).isoformat()
    }

# ─────────────────────────────────────────────
# QR Payload
# ─────────────────────────────────────────────
def build_qr_payload(session, document_id, text, entity_count):

    doc_hash = hashlib.sha256(text.encode()).hexdigest()

    payload = {
        "session_id": session["session_id"],
        "op_commitment": session["op_commitment"],
        "document_id": document_id,
        "doc_hash": doc_hash,
        "entity_count": entity_count,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    canonical = json.dumps(payload, sort_keys=True)
    payload["signature"] = _hmac(QR_SIGNING_KEY, canonical)

    return payload

# ─────────────────────────────────────────────
# Verification
# ─────────────────────────────────────────────
def verify_qr(payload, document_text, candidate_operator=None):

    sig = payload.pop("signature")
    canonical = json.dumps(payload, sort_keys=True)

    expected = _hmac(QR_SIGNING_KEY, canonical)

    sig_valid = hmac.compare_digest(sig, expected)

    doc_hash = hashlib.sha256(document_text.encode()).hexdigest()
    doc_match = hmac.compare_digest(doc_hash, payload["doc_hash"])

    op_verified = None
    if candidate_operator:
        op_verified = verify_operator(candidate_operator, payload["op_commitment"])

    return {
        "signature_valid": sig_valid,
        "document_match": doc_match,
        "operator_verified": op_verified
    }