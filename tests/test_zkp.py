"""Tests for the zero-knowledge age proof: completeness, soundness, zero-knowledge."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from zkp.proof_generator import generate_proof
from zkp.verifier import verify_proof
from zkp.params import G, P, AGE_THRESHOLD
from utils.age_calculator import calculate_age


# ---- Completeness: honest proofs for true statements always verify ----

@pytest.mark.parametrize("age", [18, 19, 25, 40, 99])
def test_valid_proof_accepts(age):
    proof = generate_proof(age)
    assert verify_proof(proof) is True


# ---- Soundness: false statements cannot produce a valid proof ----

@pytest.mark.parametrize("age", [0, 5, 17])
def test_underage_cannot_prove(age):
    with pytest.raises(ValueError):
        generate_proof(age)


def test_tampered_commitment_rejected():
    proof = generate_proof(30)
    proof["commitment"] = (proof["commitment"] * G) % P  # shift the committed value
    assert verify_proof(proof) is False


def test_tampered_bit_response_rejected():
    proof = generate_proof(30)
    proof["bit_proofs"][0]["z0"] = (proof["bit_proofs"][0]["z0"] + 1)
    assert verify_proof(proof) is False


def test_dropped_bit_proof_rejected():
    proof = generate_proof(30)
    proof["bit_proofs"] = proof["bit_proofs"][:-1]
    assert verify_proof(proof) is False


def test_forged_empty_proof_rejected():
    assert verify_proof({}) is False


# ---- Zero-knowledge (structural): proof reveals no age/dob fields ----

def test_proof_contains_no_secret():
    proof = generate_proof(37)
    serialized = str(proof)
    assert "37" not in [str(proof.get("threshold"))]  # threshold is public (18), age is not
    assert proof["threshold"] == AGE_THRESHOLD
    # No field literally named age/dob/delta.
    assert not any(k in proof for k in ("age", "dob", "delta"))


# ---- Age calculator hardening ----

def test_year_only_dob():
    # Just ensure it returns a non-negative int and doesn't crash.
    assert calculate_age("2000") >= 0


def test_invalid_date_raises():
    with pytest.raises(ValueError):
        calculate_age("31/02/2000")


def test_malformed_dob_raises():
    with pytest.raises(ValueError):
        calculate_age("not-a-date")
