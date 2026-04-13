import hmac
import hashlib
import secrets
import re
import uuid
import json
import base64
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from typing import Optional
import spacy
import qrcode
import qrcode.image.svg
from io import BytesIO

# ─────────────────────────────────────────────────────────────────────────────
# Key management
# TWO separate salts — patient PII and operator identity are cryptographically
# isolated. Compromise of one salt does NOT compromise the other.
# In production: load both from HSM / AWS Secrets Manager.
# ─────────────────────────────────────────────────────────────────────────────
SECRET_SALT: bytes = secrets.token_bytes(32)       # for patient PII
OPERATOR_SALT: bytes = secrets.token_bytes(32)     # for operator identity
QR_SIGNING_KEY: bytes = secrets.token_bytes(32)    # for QR payload integrity

nlp = spacy.load("en_core_web_trf")


# ─────────────────────────────────────────────────────────────────────────────
# Operator identity structures
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class OperatorSession:
    session_id: str          # UUID4 — public identifier for this run
    op_commitment: str       # HMAC(OPERATOR_SALT, operator_id) — no name stored
    role: str                # e.g. "data_officer", "reviewer", "admin"
    issued_at: str           # ISO timestamp
    expires_at: str          # ISO timestamp
    # operator_id / name is INTENTIONALLY absent


@dataclass
class ZKCommitment:
    token: str
    entity_type: str
    commitment: str          # HMAC(SECRET_SALT, entity_value)
    generalised: str
    processed_at: str
    session_id: str          # links this commitment to the operator session
    # original_value INTENTIONALLY absent


# ─────────────────────────────────────────────────────────────────────────────
# Core cryptographic functions
# ─────────────────────────────────────────────────────────────────────────────
def _hmac(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()

def make_commitment(original_value: str) -> str:
    """Patient PII commitment — uses SECRET_SALT."""
    return _hmac(SECRET_SALT, original_value)

def make_operator_commitment(operator_id: str) -> str:
    """
    Operator identity commitment — uses OPERATOR_SALT (separate key).
    Even if patient salt is leaked, operator identities stay protected.
    """
    return _hmac(OPERATOR_SALT, operator_id)

def verify_commitment(candidate: str, stored: str) -> bool:
    return hmac.compare_digest(make_commitment(candidate), stored)

def verify_operator_commitment(candidate_id: str, stored: str) -> bool:
    return hmac.compare_digest(make_operator_commitment(candidate_id), stored)


# ─────────────────────────────────────────────────────────────────────────────
# Operator session management
# ─────────────────────────────────────────────────────────────────────────────
def create_operator_session(operator_id: str, role: str = "data_officer") -> OperatorSession:
    """
    Called at login. operator_id is used ONCE to compute commitment,
    then is not stored anywhere in the system.
    
    Returns a session object with no PII — only a commitment and a UUID.
    """
    now = datetime.now(timezone.utc)
    session = OperatorSession(
        session_id=str(uuid.uuid4()),
        op_commitment=make_operator_commitment(operator_id),
        role=role,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=8)).isoformat(),
    )
    # operator_id goes out of scope here — never persisted
    return session

def session_is_valid(session: OperatorSession) -> bool:
    expires = datetime.fromisoformat(session.expires_at)
    return datetime.now(timezone.utc) < expires


# ─────────────────────────────────────────────────────────────────────────────
# QR proof generation
# ─────────────────────────────────────────────────────────────────────────────
def build_qr_payload(
    session: OperatorSession,
    document_id: str,
    doc_text: str,
    entity_count: int
) -> dict:
    """
    Constructs the QR payload. Contains:
      - session_id (UUID — public, linkable to audit log)
      - op_commitment (proves WHICH operator, without naming them)
      - doc_hash (proves WHICH document was processed)
      - entity_count (how many PII fields were anonymised)
      - timestamp
      - HMAC signature over all fields (tamper-evident)
    
    Anyone scanning this QR can verify:
      1. The document hash matches the document they're holding
      2. The session_id exists in the audit log
      3. The signature is valid (i.e. not forged)
      4. An authorised operator ran this (via verify_operator_commitment)
    WITHOUT knowing who the operator is.
    """
    doc_hash = hashlib.sha256(doc_text.encode("utf-8")).hexdigest()

    payload = {
        "version": "1.0",
        "session_id": session.session_id,
        "op_commitment": session.op_commitment,
        "op_role": session.role,
        "document_id": document_id,
        "doc_hash": doc_hash,
        "entity_count": entity_count,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": session.expires_at,
    }

    # Sign the payload to make it tamper-evident
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["signature"] = _hmac(QR_SIGNING_KEY, canonical)

    return payload


def generate_qr_code(payload: dict) -> bytes:
    """
    Encodes the QR payload as base64 JSON and renders a QR code PNG.
    Returns PNG bytes — embed in PDF or attach to document.
    """
    encoded = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode()

    qr = qrcode.QRCode(
        version=None,          # auto-size
        error_correction=qrcode.constants.ERROR_CORRECT_H,  # 30% damage tolerance
        box_size=6,
        border=4,
    )
    qr.add_data(encoded)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# QR verification (auditor-facing)
# ─────────────────────────────────────────────────────────────────────────────
def verify_qr_payload(
    encoded_payload: str,
    document_text: str,
    candidate_operator_id: Optional[str] = None
) -> dict:
    """
    Called when an auditor scans a QR code.
    
    Returns:
      - signature_valid: payload was not tampered with
      - document_match: QR was generated for THIS document
      - operator_verified: (only if candidate_operator_id provided)
        proves the operator committed to this session
      - session_expired: whether the session window has passed
    
    NEVER logs candidate_operator_id. NEVER stores it.
    """
    try:
        raw = json.loads(base64.b64decode(encoded_payload).decode())
    except Exception:
        return {"error": "Invalid QR payload — could not decode"}

    # Verify signature
    sig = raw.pop("signature", None)
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    expected_sig = _hmac(QR_SIGNING_KEY, canonical)
    sig_valid = hmac.compare_digest(sig or "", expected_sig)

    # Verify document hash
    doc_hash = hashlib.sha256(document_text.encode("utf-8")).hexdigest()
    doc_match = hmac.compare_digest(doc_hash, raw.get("doc_hash", ""))

    # Optionally verify operator identity
    op_verified = None
    if candidate_operator_id is not None:
        op_verified = verify_operator_commitment(
            candidate_operator_id,
            raw.get("op_commitment", "")
        )
        # candidate_operator_id goes out of scope — never stored

    # Check expiry
    try:
        expires = datetime.fromisoformat(raw["expires_at"])
        session_expired = datetime.now(timezone.utc) > expires
    except Exception:
        session_expired = True

    return {
        "signature_valid": sig_valid,
        "document_match": doc_match,
        "operator_verified": op_verified,   # None if not checked
        "session_expired": session_expired,
        "session_id": raw.get("session_id"),
        "op_role": raw.get("op_role"),
        "entity_count": raw.get("entity_count"),
        "processed_at": raw.get("processed_at"),
        # op_commitment intentionally not echoed — use it only for verify
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entity detection (unchanged)
# ─────────────────────────────────────────────────────────────────────────────
REGEX_PATTERNS = {
    "AADHAAR": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    "PHONE":   r"\b[6-9]\d{9}\b",
    "EMAIL":   r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "MRN":     r"\b(?:MRN|Reg\.?\s*No\.?|Patient\s*ID)[:\s]?[\w/\-]+\b",
    "AGE":     r"\b(\d{1,3})\s*(?:years?|yrs?|y\.o\.)\b",
    "PINCODE": r"\b[1-9]\d{5}\b",
}
NER_TYPES = {"PERSON", "GPE", "LOC", "DATE", "ORG"}

def detect_entities(text: str) -> list[dict]:
    entities = []
    seen_spans = set()
    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ in NER_TYPES:
            key = (ent.start_char, ent.end_char)
            if key not in seen_spans:
                entities.append({"text": ent.text, "start": ent.start_char,
                                  "end": ent.end_char, "label": ent.label_})
                seen_spans.add(key)
    for label, pattern in REGEX_PATTERNS.items():
        for m in re.finditer(pattern, text, re.IGNORECASE):
            key = (m.start(), m.end())
            if key not in seen_spans:
                entities.append({"text": m.group(), "start": m.start(),
                                  "end": m.end(), "label": label})
                seen_spans.add(key)
    return sorted(entities, key=lambda e: e["start"], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# Generalisation (unchanged)
# ─────────────────────────────────────────────────────────────────────────────
INDIA_STATE_MAP = {
    "bengaluru": "Karnataka", "mumbai": "Maharashtra",
    "delhi": "Delhi", "chennai": "Tamil Nadu",
    "hyderabad": "Telangana", "kolkata": "West Bengal",
}

def generalise(entity_type: str, original: str) -> str:
    et = entity_type.upper()
    if et == "AGE":
        m = re.search(r"\d+", original)
        if m:
            age = int(m.group())
            low = (age // 10) * 10
            return f"{low}-{low + 9} years"
        return "[AGE_RANGE]"
    if et == "DATE":
        m = re.search(r"(\w+\s+\d{4}|\d{4})", original)
        return m.group() if m else "[DATE_PERIOD]"
    if et in ("GPE", "LOC", "LOCATION"):
        return INDIA_STATE_MAP.get(original.strip().lower(), "India")
    return f"[{et}_REDACTED]"


# ─────────────────────────────────────────────────────────────────────────────
# Main pipeline — now operator-aware
# ─────────────────────────────────────────────────────────────────────────────
def zk_anonymise(
    text: str,
    session: OperatorSession,
    document_id: str = "UNKNOWN"
) -> dict:
    """
    Full pipeline. Now accepts an OperatorSession.
    Every commitment is tagged with session_id (not operator name).
    Returns anonymised text + audit log + QR code PNG bytes.
    """
    if not session_is_valid(session):
        raise ValueError("Operator session has expired. Please re-authenticate.")

    entities = detect_entities(text)
    commitments: list[ZKCommitment] = []
    result = text
    counters: dict[str, int] = {}

    for ent in entities:
        label = ent["label"]
        original = ent["text"]
        counters[label] = counters.get(label, 0) + 1
        token = f"[{label}_{counters[label]:03d}]"

        result = result[:ent["start"]] + token + result[ent["end"]:]

        commitment = ZKCommitment(
            token=token,
            entity_type=label,
            commitment=make_commitment(original),
            generalised=generalise(label, original),
            processed_at=datetime.now(timezone.utc).isoformat(),
            session_id=session.session_id,   # ← operator link, no name
        )
        commitments.append(commitment)

    final_text = result
    for c in commitments:
        final_text = final_text.replace(c.token, c.generalised)

    # Build and encode QR proof
    qr_payload = build_qr_payload(session, document_id, text, len(commitments))
    qr_png = generate_qr_code(qr_payload)

    return {
        "anonymised_text": final_text,
        "pseudonymised_text": result,
        "entity_count": len(commitments),
        "audit_log": [asdict(c) for c in commitments],
        "qr_payload": qr_payload,    # store in DB for audit lookups
        "qr_png": qr_png,            # embed in output PDF
        "session_id": session.session_id,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Usage example
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # 1. Operator logs in — identity committed, then discarded
    session = create_operator_session(
        operator_id="EMP-4821",   # used once, never stored
        role="data_officer"
    )
    print(f"Session: {session.session_id}")
    print(f"Op commitment: {session.op_commitment[:16]}...")

    # 2. Run anonymisation
    sample = "Patient Rahul Sharma, 34 years, Bengaluru. Aadhaar: 2345 6789 0123. Phone: 9845012345."
    result = zk_anonymise(sample, session, document_id="CDSCO-SAE-2024-0483")

    print(f"\nAnonymised: {result['anonymised_text']}")
    print(f"Entities processed: {result['entity_count']}")
    print(f"QR PNG size: {len(result['qr_png'])} bytes")

    # 3. Auditor scans QR (they have the document + QR, not the operator name)
    encoded = base64.b64encode(
        json.dumps(result["qr_payload"], separators=(",", ":")).encode()
    ).decode()

    verification = verify_qr_payload(
        encoded_payload=encoded,
        document_text=sample,
        candidate_operator_id="EMP-4821"   # optional — only if auditor suspects specific person
    )
    print(f"\nQR verification result: {verification}")