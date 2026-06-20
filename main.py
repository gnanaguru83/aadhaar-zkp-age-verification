"""
End-to-end demo: OCR -> DOB -> age -> zero-knowledge proof -> verification.

The prover proves "age >= 18" without revealing the date of birth. The verifier
checks the proof and learns only that single fact.
"""

import os

from utils.age_calculator import calculate_age
from zkp.proof_generator import generate_proof
from zkp.verifier import verify_proof

IMAGE_PATH = "images/aadhaar_sample.png"

# Fallback DOB used only when no image is available, so the demo always runs.
# (Use synthetic data only -- never commit real ID details.)
DEMO_FALLBACK_DOB = "01/01/2000"

print("\n--- Aadhaar OCR & Zero-Knowledge Age Proof ---\n")


def get_dob() -> str:
    """Extract DOB from the Aadhaar image, falling back to demo data."""
    if not os.path.exists(IMAGE_PATH):
        print(f"[!] Image '{IMAGE_PATH}' not found. Using demo DOB {DEMO_FALLBACK_DOB}.")
        return DEMO_FALLBACK_DOB
    try:
        from ocr.extract_text import extract_text, extract_dob

        print("[1] Extracting text from Aadhaar image...")
        text = extract_text(IMAGE_PATH)
        dob = extract_dob(text)
        if dob:
            print(f"    DOB detected: {dob}")
            return dob
        print("[!] DOB not found in image. Using demo DOB.")
    except Exception as exc:  # OCR / Tesseract not available, bad image, etc.
        print(f"[!] OCR unavailable ({exc}). Using demo DOB {DEMO_FALLBACK_DOB}.")
    return DEMO_FALLBACK_DOB


def main() -> None:
    dob = get_dob()

    # Step 1: compute age (sensitive).
    age = calculate_age(dob)
    print(f"[2] Age computed from DOB (kept private).")

    # Step 2: prover builds a zero-knowledge proof that age >= 18.
    try:
        proof = generate_proof(age)
    except ValueError as exc:
        print(f"[3] Proof generation refused: {exc}")
        return
    print("[3] Zero-knowledge proof generated (reveals nothing about the DOB).")

    # Step 3: discard sensitive data before verification.
    dob = None
    age = None

    # Step 4: verifier checks the proof with no access to age or DOB.
    is_valid = verify_proof(proof)
    print(f"[4] Verifier result: {'ACCEPT' if is_valid else 'REJECT'}")
    print(f"    Claim verified: {proof['claim']}")
    print("    The verifier learned ONLY that the age threshold is met.\n")


if __name__ == "__main__":
    main()
