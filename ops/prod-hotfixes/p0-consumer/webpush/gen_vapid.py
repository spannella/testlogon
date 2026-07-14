#!/usr/bin/env python3
"""Generate a VAPID (RFC 8292) keypair for TestLogon web push, in EXACTLY the
formats the running code expects. Deps: only `cryptography` (already in the venv).

Emits:
  VAPID_PUBLIC_KEY  = base64url(uncompressed EC P-256 point, 65 bytes, 0x04-prefixed)
                      -> returned by GET /ui/push/vapid-key, used by the browser as
                         PushManager.subscribe({applicationServerKey}).
  VAPID_PRIVATE_KEY = base64url(raw 32-byte private scalar)
                      -> app/services/push.py:web_push_send passes this string to
                         pywebpush.webpush(vapid_private_key=...), which calls
                         py_vapid Vapid.from_string(): it strips newlines, b64url-decodes,
                         and treats a 32-byte result as the RAW key. *** PEM WILL NOT WORK ***
                         (from_string has no `-----BEGIN` branch -> "Could not deserialize").
  VAPID_SUBJECT     = mailto: contact (any valid mailto/https URL).

Usage:  python3 gen_vapid.py
Then set the three env vars in the prod backend environment + PUSH_ENABLED=1 and
restart via restart_backend.sh. Rotating keys invalidates all existing browser
subscriptions (they must re-subscribe); the SPA re-fetches the public key at runtime,
so no web rebuild is needed to rotate.
"""
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def main() -> None:
    pk = ec.generate_private_key(ec.SECP256R1())
    priv = b64url(pk.private_numbers().private_value.to_bytes(32, "big"))
    pub_point = pk.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    pub = b64url(pub_point)
    print(f"VAPID_PUBLIC_KEY={pub}")
    print(f"VAPID_PRIVATE_KEY={priv}")
    print("VAPID_SUBJECT=mailto:admin@testlogon.local")


if __name__ == "__main__":
    main()
