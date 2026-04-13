# 🔐 NIYAM — ZK-Based Privacy-Preserving Anonymisation System (Complete Overview)

---

# 📌 1. Problem Context

Regulatory systems like CDSCO process **highly sensitive data (PII + PHI)**.

Challenges:

* Privacy risk during AI processing
* Re-identification from anonymised data
* Lack of auditability
* Compliance with DPDP, NDHM, ICMR

👉 Requirement:
A system that ensures:

* **No PII exposure**
* **Verifiable processing**
* **Statistical privacy guarantees**

---

# 🎯 2. Solution Overview

NIYAM implements a **2-layer privacy architecture**:

### 🔷 Layer 1 — Patient Privacy

* Detect → anonymise → generalise → remove identity

### 🔷 Layer 2 — Operator Accountability

* Verify *who processed the data*
* Without exposing operator identity

---

👉 Core Idea:

> **We do not store data — we store cryptographic proofs of data.**

---

# 🧠 3. ZK-Inspired Commitment System

We use a **commitment scheme based on HMAC**:

```text
commitment = HMAC(secret_key, value)
```

### Properties:

* **Hiding** → original value cannot be recovered
* **Binding** → cannot alter committed value
* **Verifiable** → correctness can be checked later

---

⚠️ Important:

> This is **ZK-inspired**, not full Zero-Knowledge Proofs.

---

# 🏗️ 4. Two-Step Anonymisation (CDSCO Requirement)

As per guidelines :

---

## Step 1 — Pseudonymisation

Replace PII with tokens:

```text
Rahul Sharma → [PERSON_001]
```

* Enables structured processing
* Maintains referential consistency

---

## Step 2 — Irreversible Anonymisation

Generalise sensitive attributes:

```text
Age 34 → 30–39  
Bengaluru → Karnataka  
Name → [REDACTED]
```

* Prevents re-identification
* Ensures compliance

---

# 🔄 5. End-to-End Pipeline

```text
Input Document
   ↓
PII Detection (NER + Regex)
   ↓
Pseudonymisation (Tokenisation)
   ↓
ZK Commitment (HMAC)
   ↓
Generalisation (Irreversible)
   ↓
Privacy Risk Check (k, l)
   ↓
Safe Output (No PII)
   ↓
QR Proof Generation (Operator Layer)
```

---

# 🔍 6. Detection Layer

Hybrid approach:

* **NER (spaCy transformer)** → names, locations
* **Regex** → Aadhaar, phone, email

👉 Ensures high recall for Indian healthcare data

---

# 🔐 7. Cryptographic Layer (ZK Commitments)

Each detected entity:

```json
{
  "token": "[PERSON_001]",
  "commitment": "a83bd91...",
  "type": "PERSON"
}
```

---

Stored:

* tokens
* commitments

NOT stored:

* ❌ names
* ❌ identifiers
* ❌ raw values

---

# 🔑 8. Key Management

Three isolated keys:

| Key            | Purpose           |
| -------------- | ----------------- |
| SECRET_SALT    | Patient PII       |
| OPERATOR_SALT  | Operator identity |
| QR_SIGNING_KEY | QR integrity      |

---

Features:

* Secure vault storage
* No hardcoding
* Key rotation supported

---

# 🧾 9. Operator Accountability Layer

---

## Goal:

Verify *who processed the data*
WITHOUT revealing identity

---

## Process:

```text
Operator ID
   ↓
HMAC(OPERATOR_SALT, operator_id)
   ↓
Session ID generated
   ↓
Linked to anonymisation process
```

---

## QR Proof Contains:

* document hash
* operator commitment
* timestamp
* entity count
* digital signature

---

## Auditor Can Verify:

* document integrity
* processing validity
* operator authenticity (if needed)

---

# 🚨 10. Statistical Inference Risk (CRITICAL)

---

## Problem:

Even anonymised data can leak identity.

Example:

```text
10 patients
1 female
→ identifiable
```

---

👉 This is called:

* attribute disclosure
* linkage attack

---

⚠️ Important:

> HMAC does NOT protect against this

---

# 🛡️ 11. Mitigation Strategy

---

## ✔ k-Anonymity

Each record belongs to a group of size ≥ k

---

## ✔ l-Diversity

Each group must have multiple attribute values

---

## ✔ Dynamic Suppression

```text
If attribute is unique → remove or generalise
```

---

## ✔ Generalisation

* Age → ranges
* Location → state
* Rare attributes → suppressed

---

## ✔ Risk Engine

```python
if unique_combination:
    generalise_or_suppress()
```

---

# ⚠️ 12. Important Clarification

---

## ❌ HMAC alone ≠ privacy

HMAC protects:

* value reversal

BUT NOT:

* statistical inference
* identity leakage

---

## ✅ Privacy requires:

* anonymisation
* generalisation
* diversity enforcement

---

# 🔬 13. Data Lifecycle

```text
Raw PII → used in memory → immediately destroyed
```

Stored:

* commitments
* tokens
* generalised output

---

👉 System is **structurally incapable of storing PII**

---

# ⚙️ 14. Design Philosophy

* ✅ Simple (HMAC, not heavy ZK)
* ✅ Secure (no PII storage)
* ✅ Deployable (FastAPI-based)
* ✅ Scalable (modular pipeline)

---

# 🏆 15. Key Strengths

* Privacy-first AI pipeline
* Verifiable anonymisation (ZK-style)
* Operator accountability without exposure
* Statistical privacy protection
* Compliance-ready

---

# ⚡ 16. Final Insight

> **Anonymisation hides identity
> ZK proves correctness
> Statistical controls prevent inference**

---

# 🟢 17. Conclusion

NIYAM provides a **simple, secure, and production-ready anonymisation system** that ensures:

* Privacy
* Auditability
* Compliance
* Trust

---

👉 Built for real-world regulatory deployment.
