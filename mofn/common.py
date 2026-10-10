import json, hashlib, base64, secrets, time, urllib.request, urllib.error
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

BASE = Path(__file__).resolve().parent
CA_DIR = BASE.parent
REGISTRY = BASE / "approvers.json"
DOMAIN_SEP = b"DEMOCA-ISSUANCE-APPROVAL-v1\n"   # domain separation: sigs are valid only for this purpose
GATEWAY = "http://127.0.0.1:8080"

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def request_id(req) -> str:
    return hashlib.sha256(canonical(req)).hexdigest()

def approval_message(req) -> bytes:
    return DOMAIN_SEP + canonical(req)

def csr_digest(csr_pem: bytes) -> str:
    csr = x509.load_pem_x509_csr(csr_pem)
    return hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest()

def csr_domains(csr_pem: bytes):
    csr = x509.load_pem_x509_csr(csr_pem)
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return sorted({d.lower() for d in san.get_values_for_type(x509.DNSName)})

def build_request(csr_pem: bytes, validity_hours: int, requester: str, ttl_seconds: int = 3600):
    return {"version": 1,
            "csr_sha256": csr_digest(csr_pem),
            "domains": csr_domains(csr_pem),
            "validity_hours": validity_hours,
            "requester": requester,
            "nonce": secrets.token_hex(16),
            "expires_at": int(time.time()) + ttl_seconds}

def load_registry():
    return json.loads(REGISTRY.read_text())

def sign_request(req, key_pem: bytes) -> str:
    key = serialization.load_pem_private_key(key_pem, password=None)
    return base64.b64encode(key.sign(approval_message(req))).decode()

def valid_approvers(req, approvals, registry) -> set:
    """Return the set of DISTINCT approver ids whose signature verifies."""
    msg = approval_message(req)
    ok = set()
    for a in approvals:
        try:
            pub_b64 = registry["approvers"].get(a["approver_id"])
            if not pub_b64:
                continue
            Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
                base64.b64decode(a["signature"]), msg)
            ok.add(a["approver_id"])
        except (InvalidSignature, ValueError, KeyError, TypeError):
            continue
    return ok

def http_call(method, path, obj=None):
    data = json.dumps(obj).encode() if obj is not None else None
    r = urllib.request.Request(GATEWAY + path, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
