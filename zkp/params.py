"""
Public cryptographic parameters for the zero-knowledge age proof.

We work in a prime-order subgroup G_q of Z_p*, where p is a 2048-bit safe
prime (p = 2q + 1, q prime). This is the standard setting for Schnorr / Pedersen
based proofs.

Two generators are used:
    g  - a generator of the order-q subgroup.
    h  - a second generator whose discrete log base g is UNKNOWN.

The "unknown discrete log" of h is what makes Pedersen commitments *binding*:
nobody can open a commitment to two different values without solving a discrete
log. We obtain such an h via a "nothing-up-my-sleeve" hash-to-group construction
so that no one (including us) knows log_g(h).
"""

import hashlib

# 2048-bit MODP safe prime (RFC 3526, Group 14). p = 2q + 1 with q prime.
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

P = int(_P_HEX, 16)
Q = (P - 1) // 2  # prime order of the subgroup of quadratic residues

# g generates the order-q subgroup. For a safe prime, the quadratic residues
# form the order-q subgroup, so squaring any base lands us inside it. 2^2 = 4.
G = pow(2, 2, P)


def _hash_to_subgroup(seed: str) -> int:
    """Deterministically derive a subgroup element with unknown log base G.

    We hash the seed to an integer and square it mod P. Squaring guarantees the
    result is a quadratic residue (i.e. lives in the order-q subgroup), and the
    discrete log of a hash output base G is not known to anyone.
    """
    digest = hashlib.sha256(seed.encode()).digest()
    candidate = int.from_bytes(digest, "big") % P
    return pow(candidate, 2, P)


# Second generator. Its discrete log base G is unknown -> commitments are binding.
H = _hash_to_subgroup("zkp-age-verification/pedersen/h-generator/v1")

# Number of bits used for the range proof. delta = age - 18 must fit in [0, 2^N).
# N = 8 covers delta up to 255 (ages up to 273), comfortably enough.
RANGE_BITS = 8

# Minimum age the proof asserts.
AGE_THRESHOLD = 18


def inv(x: int, modulus: int = P) -> int:
    """Modular inverse."""
    return pow(x, -1, modulus)


def challenge(*values: int) -> int:
    """Fiat-Shamir challenge: hash the transcript values into a scalar mod Q.

    Using a hash as the verifier's "random" challenge makes the interactive
    protocol non-interactive: the prover can produce a self-contained proof
    that any verifier can check without a live back-and-forth.
    """
    hasher = hashlib.sha256()
    hasher.update(b"zkp-age-verification/fiat-shamir/v1")
    for v in values:
        # Length-prefix each value to avoid ambiguity between concatenations.
        b = int(v).to_bytes((int(v).bit_length() + 7) // 8 or 1, "big")
        hasher.update(len(b).to_bytes(4, "big"))
        hasher.update(b)
    return int.from_bytes(hasher.digest(), "big") % Q
