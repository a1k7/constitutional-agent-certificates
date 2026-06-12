#!/usr/bin/env python3
"""
End-to-end demo of Constitutional Agent Certificates.
1. Authority generates key pair.
2. Agent creates certificate request.
3. Authority issues certificate.
4. Another agent verifies certificate and challenges continuity.
"""

import subprocess
import json
import time
import os
from cac_utils import generate_keypair, serialize_public_key, base64_encode

def run_command(cmd):
    print(f">>> {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def main():
    print("=== Constitutional Agent Certificates Demo ===\n")

    # Step 1: Authority generates key pair
    print("1. Authority generates key pair")
    run_command("python cac_authority.py --genkey")

    # Step 2: Agent creates request
    print("\n2. Agent creates certificate request")
    from agent_cac import ConstitutionalAgent
    agent = ConstitutionalAgent("agent_alice", "constitution_v1.json")
    req = agent.create_certificate_request(governance_score=94)
    with open("cert_request.json", "w") as f:
        json.dump(req, f, indent=2)
    print("   Request saved to cert_request.json")

    # Step 3: Authority issues certificate
    print("\n3. Authority issues certificate")
    run_command("python cac_authority.py --issue cert_request.json")

    # Step 4: Agent loads certificate
    agent.load_certificate("agent_certificate.json")
    print("   Agent loaded certificate")

    # Step 5: Simulate continuity challenge – agent signs its current snapshot
    print("\n4. Agent prepares continuity proof")
    proof = agent.prove_continuity()
    with open("continuity_proof.json", "w") as f:
        json.dump(proof, f, indent=2)
    print("   Proof saved to continuity_proof.json")

    # Step 6: Verifier checks certificate and challenges agent
    print("\n5. Verifier checks certificate")
    run_command("python verifier.py agent_certificate.json --challenge")

    print("\n=== Demo complete ===")
    print("Certificate valid, continuity proof accepted.")
    print("Agent A can now trust Agent B based on CAC.")

if __name__ == "__main__":
    main()