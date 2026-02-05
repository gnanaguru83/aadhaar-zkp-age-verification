from ocr.extract_text import extract_text, extract_dob
from utils.age_calculator import calculate_age
from zkp.proof_generator import generate_proof

IMAGE_PATH = "images/aadhaar_sample.png"

print("\n--- Aadhaar OCR & Age Proof Generation ---\n")

# Step 1: OCR
print("[1] Extracting text from Aadhaar image...\n")
text = extract_text(IMAGE_PATH)
print("----- OCR TEXT START -----")
print(text)
print("----- OCR TEXT END -----\n")

# Step 2: Extract DOB
print("[2] Extracting DOB from OCR text...")
dob = extract_dob(text)

if not dob:
    print("❌ DOB NOT FOUND")
    exit()

print(f"✅ DOB DETECTED: {dob}")

# Step 3: Calculate Age
age = calculate_age(dob)
print(f"[3] Calculated Age: {age}")

# Step 4: Generate Proof
proof = generate_proof(age)

print("\n[4] Privacy-Preserving Proof Generated")
print("----- PROOF -----")
for k, v in proof.items():
    print(f"{k}: {v}")

print("\n✅ 30% PROVER-SIDE IMPLEMENTATION COMPLETE")

# Discard sensitive data
dob = None
text = None
