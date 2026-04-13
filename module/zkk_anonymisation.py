import hmac
import hashlib
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime
import spacy

# Load key from environment (FIXED)
SECRET_SALT = os.environ.get("SECRET_SALT", "dev_secret").encode()

nlp = spacy.load("en_core_web_trf")

# ─────────────────────────────────────────────
# Utils
# ─────────────────────────────────────────────
def normalize(value: str) -> str:
    return value.strip().lower()

# ─────────────────────────────────────────────
# Data Structure
# ─────────────────────────────────────────────
@dataclass
class ZKCommitment:
    token: str
    entity_type: str
    commitment: str
    generalised: str
    processed_at: str
    key_version: str = "v1"

# ─────────────────────────────────────────────
# HMAC Commitment (with context binding)
# ─────────────────────────────────────────────
def make_commitment(value: str, context: str) -> str:
    value = normalize(value)
    data = value + "|" + context
    return hmac.new(SECRET_SALT, data.encode(), hashlib.sha256).hexdigest()

def verify_commitment(value: str, stored: str, context: str) -> bool:
    recomputed = make_commitment(value, context)
    return hmac.compare_digest(recomputed, stored)

# ─────────────────────────────────────────────
# Detection
# ─────────────────────────────────────────────
REGEX_PATTERNS = {
    "AADHAAR": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    "PHONE": r"\b[6-9]\d{9}\b",
    "EMAIL": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "AGE": r"\b(\d{1,3})\s*(?:years?|yrs?)\b",
}

NER_TYPES = {"PERSON", "GPE", "DATE"}

def detect_entities(text: str):
    entities = []
    doc = nlp(text)

    for ent in doc.ents:
        if ent.label_ in NER_TYPES:
            entities.append({
                "text": ent.text,
                "start": ent.start_char,
                "end": ent.end_char,
                "label": ent.label_
            })

    for label, pattern in REGEX_PATTERNS.items():
        for m in re.finditer(pattern, text):
            entities.append({
                "text": m.group(),
                "start": m.start(),
                "end": m.end(),
                "label": label
            })

    return sorted(entities, key=lambda x: x["start"], reverse=True)

# ─────────────────────────────────────────────
# Generalisation
# ─────────────────────────────────────────────
def generalise(label: str, value: str):
    if label == "AGE":
        age = int(re.search(r"\d+", value).group())
        return f"{(age//10)*10}-{(age//10)*10+9}"
    if label in ["GPE"]:
        return "STATE"
    return f"[{label}_REDACTED]"

# ─────────────────────────────────────────────
# Main Pipeline
# ─────────────────────────────────────────────
def zk_anonymise(text: str, document_id: str = "doc1"):

    entities = detect_entities(text)
    result = text
    commitments = []
    counters = {}

    for ent in entities:
        label = ent["label"]
        original = ent["text"]

        counters[label] = counters.get(label, 0) + 1
        token = f"[{label}_{counters[label]:03d}]"

        # replace safely (reverse sorted)
        result = result[:ent["start"]] + token + result[ent["end"]:]

        commitment = ZKCommitment(
            token=token,
            entity_type=label,
            commitment=make_commitment(original, document_id),
            generalised=generalise(label, original),
            processed_at=datetime.utcnow().isoformat()
        )

        commitments.append(commitment)

        # 🔥 destroy raw value
        del original

    final_text = result
    for c in commitments:
        final_text = final_text.replace(c.token, c.generalised)

    return {
        "anonymised_text": final_text,
        "audit_log": [asdict(c) for c in commitments]
    }