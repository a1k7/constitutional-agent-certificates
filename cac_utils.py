#!/usr/bin/env python3
"""
Common utilities for Constitutional Agent Certificates (CAC).
"""

import json
import hashlib
import base64
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

# ------------------------------------------------------------
# Data structures
# ------------------------------------------------------------
@dataclass
class ContinuitySnapshot:
    """Snapshot of agent's current governance state (Layer 3)."""
    observer_identity_hash: str
    reference_frame_hash: str
    timestamp: float

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'))

@dataclass
class CertificateRequest:
    """Request sent to authority to obtain a certificate."""
    agent_id: str
    constitution_hash: str
    initial_snapshot: ContinuitySnapshot
    governance_score: float
    public_key: bytes  # raw public key bytes
    validity_seconds: int = 300  # 5 minutes

    def to_canonical_json(self) -> str:
        data = {
            "agent_id": self.agent_id,
            "constitution_hash": self.constitution_hash,
            "initial_snapshot": self.initial_snapshot.to_dict(),
            "governance_score": self.governance_score,
            "public_key_base64": base64.b64encode(self.public_key).decode(),
            "validity_seconds": self.validity_seconds
        }
        return json.dumps(data, sort_keys=True, separators=(',', ':'))

@dataclass
class Certificate:
    """Signed certificate (Layer 1 + 2 + 3)."""
    agent_id: str
    constitution_hash: str
    snapshot_hash: str  # hash of the initial ContinuitySnapshot
    governance_score: float
    public_key_base64: str
    issued_at: float
    expires_at: float
    issuer_signature_base64: str

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_canonical_json(self) -> str:
        # Exclude signature field
        data = {k:v for k,v in asdict(self).items() if k != 'issuer_signature_base64'}
        return json.dumps(data, sort_keys=True, separators=(',', ':'))

# ------------------------------------------------------------
# Cryptographic helpers
# ------------------------------------------------------------
def generate_keypair() -> (Ed25519PrivateKey, Ed25519PublicKey):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def serialize_public_key(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes_raw()

def deserialize_public_key(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)

def sign_data(key: Ed25519PrivateKey, data: bytes) -> bytes:
    return key.sign(data)

def verify_signature(pub: Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    try:
        pub.verify(signature, data)
        return True
    except Exception:
        return False

def compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()

def base64_encode(b: bytes) -> str:
    return base64.b64encode(b).decode()

def base64_decode(s: str) -> bytes:
    return base64.b64decode(s)