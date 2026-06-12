#!/usr/bin/env python3
"""
Verify a Constitutional Agent Certificate and optionally challenge continuity.
"""

import json
import sys
import time
import base64
from cac_utils import (
    deserialize_public_key, verify_signature, compute_hash,
    base64_decode, ContinuitySnapshot
)

def verify_certificate(cert_file: str, authority_pub_file: str) -> bool:
    with open(cert_file, 'r') as f:
        cert = json.load(f)
    with open(authority_pub_file, 'rb') as f:
        authority_pub_raw = f.read()
    pub_key = deserialize_public_key(authority_pub_raw)

    # Extract signature
    signature_b64 = cert.pop('issuer_signature_base64', None)
    if not signature_b64:
        print("❌ Certificate missing signature")
        return False

    # Recompute canonical certificate (without signature)
    canonical = json.dumps(cert, sort_keys=True, separators=(',', ':'))
    valid = verify_signature(pub_key, canonical.encode(), base64_decode(signature_b64))
    if not valid:
        print("❌ Certificate signature invalid")
        return False

    # Check expiry
    if cert['expires_at'] < time.time():
        print("❌ Certificate expired")
        return False

    print("✅ Certificate signature valid and not expired")
    return True

def challenge_continuity(agent_url: str, cert_file: str, expected_agent_id: str):
    """
    Simulates challenging an agent via HTTP (here just a demo stub).
    In real implementation, you would send a POST to /prove.
    """
    print(f"🔍 Challenging agent {expected_agent_id} for continuity proof...")
    # Here we would normally send an HTTP request.
    # For demo, we assume the agent provides a proof file.
    try:
        with open("continuity_proof.json", "r") as f:
            proof = json.load(f)
    except FileNotFoundError:
        print("   No proof file found. Run agent to generate proof.")
        return False

    if proof['agent_id'] != expected_agent_id:
        print("❌ Agent ID mismatch")
        return False

    # Verify signature over snapshot
    snapshot = ContinuitySnapshot(**proof['snapshot'])
    canonical = snapshot.to_canonical_json()
    sig = base64_decode(proof['signature_base64'])

    # Load agent's public key from certificate
    with open(cert_file, 'r') as f:
        cert = json.load(f)
    agent_pub_raw = base64_decode(cert['public_key_base64'])
    agent_pub = deserialize_public_key(agent_pub_raw)

    if verify_signature(agent_pub, canonical.encode(), sig):
        print("✅ Continuity proof valid – agent is still admissible")
        return True
    else:
        print("❌ Continuity proof invalid – agent authority may have drifted")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verifier.py <certificate.json> [--challenge]")
        sys.exit(1)

    cert_file = sys.argv[1]
    ok = verify_certificate(cert_file, "authority_public.bin")
    if not ok:
        sys.exit(1)

    if len(sys.argv) > 2 and sys.argv[2] == '--challenge':
        # For demo, we read the agent's proof from a file.
        # In a real scenario, you would do an HTTP request.
        challenge_continuity(None, cert_file, "agent_alice")