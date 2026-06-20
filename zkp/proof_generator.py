"""
Prover side of the zero-knowledge age proof.

Goal: prove "age >= 18" WITHOUT revealing the age (or date of birth).

Technique:
  1. Let delta = age - AGE_THRESHOLD. Proving age >= 18 is equivalent to
     proving delta >= 0, i.e. delta lies in the range [0, 2^N).
  2. Commit to delta with a Pedersen commitment  C = g^delta * h^r.
  3. Prove (in zero knowledge) that the committed value lies in [0, 2^N) using
     a bit-decomposition range proof:
        - write delta = sum_i b_i * 2^i with each b_i in {0,1}
        - commit to each bit:  C_i = g^{b_i} * h^{r_i}
        - prove each C_i opens to 0 OR 1  (Schnorr OR-proof)
        - the verifier checks that prod_i C_i^{2^i} == C, which ties the bits
          back to delta.

Everything is made non-interactive with the Fiat-Shamir transform.

The verifier learns ONLY that age >= 18. It never sees age, delta, or the DOB.
"""

import secrets

from zkp.params import P, Q, G, H, RANGE_BITS, AGE_THRESHOLD, inv, challenge


def _rand_scalar() -> int:
    """A cryptographically secure random scalar in [0, Q)."""
    return secrets.randbelow(Q)


def _commit(value: int, blind: int) -> int:
    """Pedersen commitment C = g^value * h^blind  (mod P)."""
    return (pow(G, value % Q, P) * pow(H, blind % Q, P)) % P


def _prove_bit(bit: int, commitment: int, blind: int) -> dict:
    """Schnorr OR-proof that `commitment` opens to 0 OR 1.

    Statement: knowledge of r such that
        commitment        = h^r        (bit == 0), OR
        commitment * g^-1 = h^r        (bit == 1).

    We run a real Schnorr proof on the true branch and SIMULATE the false one,
    then bind them together so exactly one challenge is "free".
    """
    # Y0 corresponds to the bit==0 statement, Y1 to bit==1.
    y0 = commitment
    y1 = (commitment * inv(G)) % P

    if bit == 0:
        # Simulate branch 1, prove branch 0 for real.
        e1 = _rand_scalar()
        z1 = _rand_scalar()
        t1 = (pow(H, z1, P) * inv(pow(y1, e1, P))) % P

        k0 = _rand_scalar()
        t0 = pow(H, k0, P)

        c = challenge(commitment, y0, y1, t0, t1)
        e0 = (c - e1) % Q
        z0 = (k0 + e0 * blind) % Q
    else:
        # Simulate branch 0, prove branch 1 for real.
        e0 = _rand_scalar()
        z0 = _rand_scalar()
        t0 = (pow(H, z0, P) * inv(pow(y0, e0, P))) % P

        k1 = _rand_scalar()
        t1 = pow(H, k1, P)

        c = challenge(commitment, y0, y1, t0, t1)
        e1 = (c - e0) % Q
        z1 = (k1 + e1 * blind) % Q

    return {"C": commitment, "t0": t0, "t1": t1, "e0": e0, "e1": e1, "z0": z0, "z1": z1}


def generate_proof(age: int) -> dict:
    """Produce a non-interactive zero-knowledge proof that age >= AGE_THRESHOLD.

    Raises ValueError if the prover is not actually old enough -- an honest
    prover cannot create a valid proof for a false statement (soundness).
    """
    delta = age - AGE_THRESHOLD
    if delta < 0:
        raise ValueError("Cannot prove age >= %d: prover is underage." % AGE_THRESHOLD)
    if delta >= (1 << RANGE_BITS):
        raise ValueError("Age out of supported range for this proof.")

    # Decompose delta into bits and commit to each bit independently.
    bit_proofs = []
    blinds = []
    for i in range(RANGE_BITS):
        b = (delta >> i) & 1
        r_i = _rand_scalar()
        blinds.append(r_i)
        c_i = _commit(b, r_i)
        bit_proofs.append(_prove_bit(b, c_i, r_i))

    # Overall commitment to delta is the weighted product of the bit commitments:
    #   prod_i C_i^{2^i} = g^{sum b_i 2^i} h^{sum r_i 2^i} = g^delta h^R
    # so we set the commitment's randomness R = sum r_i 2^i and the verifier can
    # reconstruct C from the bit commitments.
    R = sum(blinds[i] * (1 << i) for i in range(RANGE_BITS)) % Q
    commitment = _commit(delta, R)

    return {
        "claim": "AGE_OVER_%d" % AGE_THRESHOLD,
        "threshold": AGE_THRESHOLD,
        "range_bits": RANGE_BITS,
        "commitment": commitment,
        "bit_proofs": bit_proofs,
    }
