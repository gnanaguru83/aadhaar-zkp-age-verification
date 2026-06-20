"""
Verifier side of the zero-knowledge age proof.

The verifier receives only the proof object (commitment + bit proofs). It checks:
  1. Each bit commitment is a valid OR-proof of {0,1}.
  2. The bit commitments multiply (weighted by powers of two) back to the
     overall commitment, tying the bits to delta = age - threshold.

If both checks pass, the verifier is convinced that age >= threshold and
learns nothing else. It never sees age, delta, or the date of birth.
"""

from zkp.params import P, Q, G, H, inv, challenge


def _verify_bit(bit_proof: dict) -> bool:
    """Verify a single Schnorr OR-proof that the commitment opens to 0 or 1."""
    c_i = bit_proof["C"]
    t0 = bit_proof["t0"]
    t1 = bit_proof["t1"]
    e0 = bit_proof["e0"]
    e1 = bit_proof["e1"]
    z0 = bit_proof["z0"]
    z1 = bit_proof["z1"]

    y0 = c_i
    y1 = (c_i * inv(G)) % P

    # The two sub-challenges must sum to the Fiat-Shamir challenge.
    c = challenge(c_i, y0, y1, t0, t1)
    if (e0 + e1) % Q != c:
        return False

    # Schnorr verification equation for each branch: h^z == t * Y^e.
    check0 = pow(H, z0, P) == (t0 * pow(y0, e0, P)) % P
    check1 = pow(H, z1, P) == (t1 * pow(y1, e1, P)) % P
    return check0 and check1


def verify_proof(proof: dict) -> bool:
    """Return True iff the proof validly demonstrates age >= threshold."""
    try:
        bit_proofs = proof["bit_proofs"]
        commitment = proof["commitment"]
        range_bits = proof["range_bits"]
    except (KeyError, TypeError):
        return False

    if len(bit_proofs) != range_bits:
        return False

    # 1. Every bit must be a valid 0/1 commitment.
    for bp in bit_proofs:
        if not _verify_bit(bp):
            return False

    # 2. The weighted product of bit commitments must equal the commitment.
    #    prod_i C_i^{2^i} == C  proves the committed value is exactly the
    #    non-negative integer formed by those bits, hence in [0, 2^range_bits).
    reconstructed = 1
    for i in range(range_bits):
        reconstructed = (reconstructed * pow(bit_proofs[i]["C"], 1 << i, P)) % P

    return reconstructed == commitment % P
