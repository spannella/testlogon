#!/usr/bin/env python3
"""Generate VAPID key pair for Web Push (PLATFORM-010).

Usage:
    python3 scripts/generate_vapid_keys.py

Output: VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY values for .env.local.

The private key is base64url-encoded raw 32-byte P-256 private key scalar.
The public key is URL-safe base64 of the uncompressed EC P-256 point (65 bytes).
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64


def generate_vapid_keys():
    """Generate a VAPID key pair and print env var values."""
    # Generate P-256 key pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Public key as URL-safe base64 of uncompressed point (65 bytes)
    public_numbers = public_key.public_numbers()
    x = public_numbers.x.to_bytes(32, "big")
    y = public_numbers.y.to_bytes(32, "big")
    uncompressed = b"\x04" + x + y  # 65 bytes: 0x04 prefix + 32 bytes x + 32 bytes y
    public_b64 = base64.urlsafe_b64encode(uncompressed).decode().rstrip("=")

    # Private key as URL-safe base64 of the raw 32-byte scalar
    private_numbers = private_key.private_numbers()
    private_bytes = private_numbers.private_value.to_bytes(32, "big")
    private_b64 = base64.urlsafe_b64encode(private_bytes).decode().rstrip("=")

    print("# Add these to .env.local:")
    print(f"VAPID_PUBLIC_KEY={public_b64}")
    print(f"VAPID_PRIVATE_KEY={private_b64}")
    print(f"VAPID_SUBJECT=mailto:admin@testlogon.local")
    print(f"WEB_PUSH_ENABLED=1")
    print()
    print(f"# Public key length: {len(public_b64)} chars (should decode to 65 bytes)")
    print(f"# Private key length: {len(private_b64)} chars (should decode to 32 bytes)")


if __name__ == "__main__":
    generate_vapid_keys()
