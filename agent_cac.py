#!/usr/bin/env python3
"""
Constitutional Agent – holds a private key, a certificate,
and can respond to continuity challenges.
"""

import json
import time
import base64
import sys
from cac_utils import (
    generate_keypair, serialize_public_key, deserialize_public_key, sign_data,
    compute_hash, verify_signature, base64_encode, base64_decode,
    ContinuitySnapshot, CertificateRequest
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class ConstitutionalAgent:
    def __init__(self, agent_id: str, constitution_path: str):
        self.agent_id = agent_id
        self.private_key, self.public_key = generate_keypair()
        self.public_key_raw = serialize_public_key(self.public_key)
        self.certificate = None
        self.constitution_hash = None
        self.current_snapshot = None

        # Load constitution and compute hash
        with open(constitution_path, 'r') as f:
            constitution = json.load(f)
        self.constitution_hash = compute_hash(json.dumps(constitution, sort_keys=True))

        # Initial snapshot
        self.update_snapshot(observer_hash="genesis_observer", ref_hash="genesis_ref")

    def update_snapshot(self, observer_hash: str, ref_hash: str):
        self.current_snapshot = ContinuitySnapshot(
            observer_identity_hash=observer_hash,
            reference_frame_hash=ref_hash,
            timestamp=time.time()
        )

    def create_certificate_request(self, governance_score: float, validity_seconds: int = 300) -> dict:
        req = CertificateRequest(
            agent_id=self.agent_id,
            constitution_hash=self.constitution_hash,
            initial_snapshot=self.current_snapshot,
            governance_score=governance_score,
            public_key=self.public_key_raw,
            validity_seconds=validity_seconds
        )
        return json.loads(req.to_canonical_json())

    def load_certificate(self, cert_file: str):
        with open(cert_file, 'r') as f:
            self.certificate = json.load(f)

    def prove_continuity(self) -> dict:
        """Returns a signed continuity proof (current snapshot) as a response to challenge."""
        if not self.certificate:
            raise ValueError("No certificate loaded")
        # Sign the current snapshot with agent's private key
        canonical = self.current_snapshot.to_canonical_json()
        signature = sign_data(self.private_key, canonical.encode())
        return {
            "agent_id": self.agent_id,
            "snapshot": self.current_snapshot.to_dict(),
            "signature_base64": base64_encode(signature)
        }

def main():
    # Demo: agent creates request, we simulate authority issuing cert
    agent = ConstitutionalAgent("agent_alice", "constitution_v1.json")
    # Create request (in real life, send to authority)
    req = agent.create_certificate_request(governance_score=94)
    with open("cert_request.json", "w") as f:
        json.dump(req, f, indent=2)
    print("✅ Created certificate request: cert_request.json")
    print("Run: python cac_authority.py --issue cert_request.json")
    print("Then agent.load_certificate('agent_certificate.json')")

if __name__ == "__main__":
    main()