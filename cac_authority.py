#!/usr/bin/env python3
"""
Constitutional Agent Certificate Authority.
Generates a key pair and issues signed certificates.
Usage:
    python cac_authority.py --issue <request_file.json>
    python cac_authority.py --genkey
"""

import sys
import json
import time
import argparse
import base64  # <-- ADD THIS IMPORT
from cac_utils import (
    generate_keypair, serialize_public_key, sign_data,
    compute_hash, Certificate, ContinuitySnapshot, CertificateRequest
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--genkey', action='store_true', help='Generate a new authority key pair')
    parser.add_argument('--issue', help='Issue a certificate from a request JSON file')
    parser.add_argument('--public-key', help='Show public key (base64)')
    args = parser.parse_args()

    if args.genkey:
        priv, pub = generate_keypair()
        with open('authority_private.pem', 'wb') as f:
            f.write(priv.private_bytes_raw())
        with open('authority_public.bin', 'wb') as f:
            f.write(serialize_public_key(pub))
        print("✅ Authority key pair generated:")
        print("   - authority_private.pem (keep secret)")
        print("   - authority_public.bin  (publish)")
        return

    if args.public_key:
        with open('authority_public.bin', 'rb') as f:
            pub_raw = f.read()
        print(base64.b64encode(pub_raw).decode())
        return

    if args.issue:
        with open(args.issue, 'r') as f:
            req_data = json.load(f)

        snapshot = ContinuitySnapshot(**req_data['initial_snapshot'])
        req = CertificateRequest(
            agent_id=req_data['agent_id'],
            constitution_hash=req_data['constitution_hash'],
            initial_snapshot=snapshot,
            governance_score=req_data['governance_score'],
            public_key=base64.b64decode(req_data['public_key_base64']),
            validity_seconds=req_data.get('validity_seconds', 300)
        )

        with open('authority_private.pem', 'rb') as f:
            priv_key = Ed25519PrivateKey.from_private_bytes(f.read())

        snapshot_hash = compute_hash(snapshot.to_canonical_json())
        issued_at = time.time()
        expires_at = issued_at + req.validity_seconds

        cert = Certificate(
            agent_id=req.agent_id,
            constitution_hash=req.constitution_hash,
            snapshot_hash=snapshot_hash,
            governance_score=req.governance_score,
            public_key_base64=base64.b64encode(req.public_key).decode(),
            issued_at=issued_at,
            expires_at=expires_at,
            issuer_signature_base64=""
        )
        canonical = cert.to_canonical_json()
        signature = sign_data(priv_key, canonical.encode())
        cert.issuer_signature_base64 = base64.b64encode(signature).decode()

        output = cert.to_dict()
        with open('agent_certificate.json', 'w') as f:
            json.dump(output, f, indent=2)
        print(f"✅ Certificate issued to {req.agent_id}")
        print(f"   Expires: {expires_at}")
        return

    print("Use --genkey or --issue <request.json>")

if __name__ == "__main__":
    main()