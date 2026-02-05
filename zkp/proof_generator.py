import hashlib
import random

def generate_proof(age):
    is_adult = age >= 18
    nonce = random.randint(100000, 999999)

    commitment = hashlib.sha256(
        f"{is_adult}{nonce}".encode()
    ).hexdigest()

    return {
        "claim": "AGE_OVER_18",
        "result": is_adult,
        "commitment": commitment,
        "nonce": nonce
    }
