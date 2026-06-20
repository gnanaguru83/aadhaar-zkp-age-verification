# Aadhaar ZKP — Zero-Knowledge Age Verification

Prove that a person is **over 18** from an Aadhaar document **without revealing their date of birth** — or anything else.

This project implements a real zero-knowledge **range proof** with a complete **prover ↔ verifier** protocol. The verifier outputs only `ACCEPT` / `REJECT` and learns nothing beyond the single fact "age ≥ 18".

---

## What it does

```
Aadhaar image ──OCR──► Date of Birth ──► Age ──► Zero-Knowledge Proof ──► Verifier ──► ACCEPT / REJECT
                                          (secret, never shared)         (learns only: age ≥ 18)
```

1. **OCR** (Tesseract) extracts the date of birth from an Aadhaar image.
2. The age is computed locally and treated as a **secret** (the *witness*).
3. The **prover** builds a non-interactive zero-knowledge proof that `age ≥ 18`.
4. The **verifier** checks the proof and accepts/rejects — without ever seeing the age or DOB.

---

## How the zero-knowledge proof works

The statement proved is `age ≥ 18`, rewritten as `delta = age − 18` lies in the range `[0, 2^N)`.

| Building block | Role |
| --- | --- |
| **Pedersen commitment** `C = g^delta · h^r` | Hides the value (`r` is random) while being binding (`log_g h` is unknown). |
| **Bit decomposition** `delta = Σ bᵢ·2ⁱ` | Each bit is committed separately as `Cᵢ = g^{bᵢ}·h^{rᵢ}`. |
| **Schnorr OR-proof** | Proves each `Cᵢ` opens to **0 or 1** without revealing which. |
| **Product check** `∏ Cᵢ^{2ⁱ} = C` | Ties the bits back to `delta`, proving it is a valid non-negative integer in range. |
| **Fiat–Shamir transform** | Replaces the verifier's random challenge with a hash, making the proof non-interactive. |

The three zero-knowledge properties hold:

- **Completeness** — an honest prover who is ≥ 18 always convinces the verifier.
- **Soundness** — an underage prover cannot produce a valid proof (tampered/forged proofs are rejected).
- **Zero-knowledge** — the verifier learns only that the statement is true.

---

## Project structure

```
zero_knowledge/
├── main.py                  # End-to-end demo: OCR → age → prove → verify
├── ocr/extract_text.py      # Tesseract OCR + multi-format DOB extraction
├── utils/age_calculator.py  # DOB → age, with validation of malformed/future dates
├── zkp/
│   ├── params.py            # Group parameters (2048-bit safe prime) + Fiat–Shamir challenge
│   ├── proof_generator.py   # Prover: Pedersen commitment + range proof
│   └── verifier.py          # Verifier: accept/reject (the missing half of a real ZKP)
└── tests/test_zkp.py        # 16 tests: completeness, soundness, ZK structure
```

---

## Quick start

```bash
# 1. (optional) create / activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

# 2. install dependencies (only needed for OCR + tests; the ZKP core is pure stdlib)
pip install -r requirements.txt

# 3. run the end-to-end demo
python main.py

# 4. run the test suite
pytest -q
```

The OCR step requires the [Tesseract engine](https://github.com/tesseract-ocr/tesseract) installed on your system. If no image or engine is available, `main.py` falls back to a synthetic demo DOB so the full prove → verify flow always runs.

---

## Example output

```
--- Aadhaar OCR & Zero-Knowledge Age Proof ---
[2] Age computed from DOB (kept private).
[3] Zero-knowledge proof generated (reveals nothing about the DOB).
[4] Verifier result: ACCEPT
    Claim verified: AGE_OVER_18
    The verifier learned ONLY that the age threshold is met.
```

---

## Scope and limitations (by design)

This is an **educational implementation** built to demonstrate zero-knowledge proof concepts end to end. It is **not** production cryptography. Known limitations and intended next steps:

- **Credential binding (most important):** the proof demonstrates knowledge of an age value, but does not yet prove that value came from a *UIDAI-signed* credential. A production version would verify the signed Aadhaar QR/offline-XML and prove the committed DOB matches the signed data.
- **Strong Fiat–Shamir:** the challenge should hash the full public statement; a hardened version would bind all public inputs.
- **Input validation:** a production verifier would validate that all proof elements lie in the correct subgroup.
- **Replay protection:** binding each proof to a verifier-supplied session nonce would prevent replay.
- Uses a finite-field (discrete-log) group rather than elliptic curves, and is not constant-time or audited.

> Real Aadhaar authentication is also legally restricted (Aadhaar Act). This project is intended for learning and uses **synthetic/test images only** — never commit real ID data.

---

## Tech stack

Python · Cryptography (Pedersen commitments, Schnorr OR-proofs, zero-knowledge range proofs, Fiat–Shamir) · Tesseract OCR · pytest
