import hmac
import hashlib
import secrets
import re
import json
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional
import spacy

# ── Key management ────────────────────────────────────────────────────────────
# In production: load from HSM / AWS Secrets Manager / environment variable.
# NEVER hardcode. NEVER store in database.
SECRET_SALT: bytes = secrets.token_bytes(32)

nlp = spacy.load("en_core_web_trf")  # transformer-based NER


# ── Data structures ───────────────────────────────────────────────────────────
@dataclass
class ZKCommitment:
    token: str            # what appears in the document
    entity_type: str      # PERSON, AGE, DATE, LOCATION, PHONE, etc.
    commitment: str       # HMAC-SHA256 — proves we held the value
    generalised: str      # what replaces the token after step 2
    processed_at: str     # ISO timestamp
    # original_value is INTENTIONALLY absent from this dataclass


# ── Core cryptographic functions ──────────────────────────────────────────────
def make_commitment(original_value: str) -> str:
    """
    Compute HMAC-SHA256(secret_salt, original_value).
    This is a cryptographic commitment: proves you held 'original_value'
    without storing it. Collision-resistant and preimage-resistant.
    """
    return hmac.new(
        SECRET_SALT,
        original_value.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_commitment(candidate_value: str, stored_commitment: str) -> bool:
    """
    Verify that 'candidate_value' matches 'stored_commitment'.
    Uses constant-time comparison to prevent timing attacks.
    """
    recomputed = make_commitment(candidate_value)
    return hmac.compare_digest(recomputed, stored_commitment)


# ── Entity detection ──────────────────────────────────────────────────────────
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
    """
    Returns a list of {text, start, end, label} dicts,
    combining spaCy NER with regex patterns.
    """
    entities = []
    seen_spans = set()

    # spaCy NER
    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ in NER_TYPES:
            key = (ent.start_char, ent.end_char)
            if key not in seen_spans:
                entities.append({
                    "text": ent.text,
                    "start": ent.start_char,
                    "end": ent.end_char,
                    "label": ent.label_
                })
                seen_spans.add(key)

    # Regex patterns
    for label, pattern in REGEX_PATTERNS.items():
        for m in re.finditer(pattern, text, re.IGNORECASE):
            key = (m.start(), m.end())
            if key not in seen_spans:
                entities.append({
                    "text": m.group(),
                    "start": m.start(),
                    "end": m.end(),
                    "label": label
                })
                seen_spans.add(key)

    # Sort by position for sequential replacement
    return sorted(entities, key=lambda e: e["start"], reverse=True)


# ── Generalisation rules ──────────────────────────────────────────────────────
INDIA_STATE_MAP = {
    "bengaluru": "Karnataka", "mumbai": "Maharashtra",
    "delhi": "Delhi", "chennai": "Tamil Nadu",
    "hyderabad": "Telangana", "kolkata": "West Bengal",
    # extend with full district→state mapping
}


def generalise(entity_type: str, original: str) -> str:
    """Step 2: irreversibly blur the entity."""
    et = entity_type.upper()

    if et == "AGE":
        m = re.search(r"\d+", original)
        if m:
            age = int(m.group())
            low = (age // 10) * 10
            return f"{low}-{low + 9} years"
        return "[AGE_RANGE]"

    if et == "DATE":
        # Retain only month and year
        m = re.search(r"(\w+\s+\d{4}|\d{4})", original)
        return m.group() if m else "[DATE_PERIOD]"

    if et in ("GPE", "LOC", "LOCATION"):
        key = original.strip().lower()
        return INDIA_STATE_MAP.get(key, "India")

    # For PERSON, PHONE, EMAIL, AADHAAR, MRN — full redaction
    return f"[{et}_REDACTED]"


# ── Main anonymisation pipeline ───────────────────────────────────────────────
def zk_anonymise(text: str) -> dict:
    """
    Full two-step ZK anonymisation pipeline.
    Returns anonymised text + audit log with ZK commitments (no PII).
    """
    entities = detect_entities(text)
    commitments: list[ZKCommitment] = []
    result = text
    counters: dict[str, int] = {}

    for ent in entities:
        label = ent["label"]
        original = ent["text"]

        # Generate sequential token
        counters[label] = counters.get(label, 0) + 1
        token = f"[{label}_{counters[label]:03d}]"

        # Step 1: pseudonymise
        result = result[:ent["start"]] + token + result[ent["end"]:]

        # ZK commitment — no original value stored
        commitment = ZKCommitment(
            token=token,
            entity_type=label,
            commitment=make_commitment(original),
            generalised=generalise(label, original),
            processed_at=datetime.utcnow().isoformat() + "Z"
        )
        commitments.append(commitment)

    # Step 2: replace tokens with generalised forms
    final_text = result
    for c in commitments:
        final_text = final_text.replace(c.token, c.generalised)

    return {
        "anonymised_text": final_text,
        "pseudonymised_text": result,   # intermediate, for debugging only
        "entity_count": len(commitments),
        "audit_log": [asdict(c) for c in commitments],
        # audit_log contains zero PII — safe to store in database
    }


# ── Verification endpoint ─────────────────────────────────────────────────────
def audit_verify(candidate_value: str, stored_commitment: str) -> dict:
    """
    Authorised auditors can verify that a specific value was processed.
    Returns True/False — does NOT log the candidate value.
    """
    result = verify_commitment(candidate_value, stored_commitment)
    return {
        "verified": result,
        "checked_at": datetime.utcnow().isoformat() + "Z"
        # candidate_value is intentionally not echoed back
    }