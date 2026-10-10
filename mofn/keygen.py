import json, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common import BASE, REGISTRY

N, M = 5, 3
reg = {"threshold": M, "approvers": {}}
for i in range(1, N + 1):
    aid = f"approver{i}"
    k = Ed25519PrivateKey.generate()
    kp = BASE / "keys" / f"{aid}.key"
    kp.write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    kp.chmod(0o600)
    reg["approvers"][aid] = base64.b64encode(k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
REGISTRY.write_text(json.dumps(reg, indent=2))
print(f"created {N} approvers, threshold {M}")
