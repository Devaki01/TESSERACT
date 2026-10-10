import os, time, json, hashlib, sqlite3, datetime
import pkcs11
from pkcs11 import Mechanism, ObjectClass
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from common import (BASE, CA_DIR, canonical, request_id, csr_digest, csr_domains,
                    load_registry, valid_approvers)

POLICY = {"max_hours": 72, "allowed_suffixes": ["test.local"],
          "allowed_curves": ["secp256r1", "secp384r1"]}
STATE_DB = BASE / "signer_state.db"
AUDIT = BASE / "audit.log"

class Denied(Exception):
    pass

# ---------- tamper-evident audit log (hash chain) ----------
def audit(event, **kw):
    prev = "0" * 64
    if AUDIT.exists():
        lines = AUDIT.read_text().splitlines()
        if lines:
            prev = json.loads(lines[-1])["hash"]
    rec = {"ts": time.time(), "event": event, **kw, "prev": prev}
    rec["hash"] = hashlib.sha256(canonical(rec)).hexdigest()
    with AUDIT.open("a") as f:
        f.write(json.dumps(rec) + "\n")

def verify_audit():
    prev = "0" * 64
    if not AUDIT.exists():
        return True, None
    for i, line in enumerate(AUDIT.read_text().splitlines()):
        rec = json.loads(line)
        h = rec.pop("hash")
        if rec["prev"] != prev or hashlib.sha256(canonical(rec)).hexdigest() != h:
            return False, i
        prev = h
    return True, None

# ---------- HSM ----------
def der(tag, c):
    n = len(c)
    l = bytes([n]) if n < 128 else (b"\x81" + bytes([n]) if n < 256 else b"\x82" + n.to_bytes(2, "big"))
    return bytes([tag]) + l + c

SIG_ALG = bytes.fromhex("300a06082a8648ce3d040303")   # ecdsa-with-SHA384

def hsm_sign(data: bytes) -> bytes:
    lib = pkcs11.lib(os.environ["P11MOD"])
    tok = lib.get_token(token_label="issuingCA")
    with tok.open(user_pin=os.environ["HSM_PIN"]) as s:   # Phase 2b: PIN comes from Shamir unseal
        k = s.get_key(label="issuing-key", object_class=ObjectClass.PRIVATE_KEY)
        raw = k.sign(hashlib.sha384(data).digest(), mechanism=Mechanism.ECDSA)
    h = len(raw) // 2
    return encode_dss_signature(int.from_bytes(raw[:h], "big"), int.from_bytes(raw[h:], "big"))

def issue_leaf(csr, domains, hours) -> str:
    issuer = x509.load_pem_x509_certificate((CA_DIR / "certs/issuing.crt").read_bytes())
    iss_pub = serialization.load_pem_public_key((CA_DIR / "certs/issuing_pub.pem").read_bytes())
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(issuer.subject)
         .public_key(csr.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(hours=hours))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
              key_encipherment=False, data_encipherment=False, key_agreement=False,
              key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
              critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)
         .add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False)  # Must-Staple
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(iss_pub), critical=False))
    tbs = b.sign(ec.generate_private_key(ec.SECP384R1()), hashes.SHA384()).tbs_certificate_bytes
    cert = x509.load_der_x509_certificate(der(0x30, tbs + SIG_ALG + der(0x03, b"\x00" + hsm_sign(tbs))))
    audit("ISSUED", serial=str(cert.serial_number), domains=domains,
          not_after=cert.not_valid_after_utc.isoformat())
    return cert.public_bytes(serialization.Encoding.PEM).decode()

# ---------- the authorization decision ----------
def _check(request, csr_pem, approvals):
    registry = load_registry()
    M = registry["threshold"]

    # 1. freshness
    if time.time() > request.get("expires_at", 0):
        raise Denied("request expired")

    # 2. bind approvals to the ACTUAL csr (gateway's claims are not trusted)
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except Exception:
        raise Denied("unparseable CSR")
    if not csr.is_signature_valid:
        raise Denied("CSR self-signature invalid")
    if csr_digest(csr_pem) != request["csr_sha256"]:
        raise Denied("CSR does not match the approved CSR hash")
    domains = csr_domains(csr_pem)
    if not domains or domains != sorted(request["domains"]):
        raise Denied("domains in CSR differ from approved domains")

    # 3. policy
    hours = request["validity_hours"]
    if not isinstance(hours, int) or not (1 <= hours <= POLICY["max_hours"]):
        raise Denied(f"validity must be 1..{POLICY['max_hours']} hours")
    for d in domains:
        if d.startswith("*"):
            raise Denied("wildcards require tier-1 onboarding")
        if not any(d == s or d.endswith("." + s) for s in POLICY["allowed_suffixes"]):
            raise Denied(f"domain not allowed by policy: {d}")
    pk = csr.public_key()
    if not (isinstance(pk, ec.EllipticCurvePublicKey) and pk.curve.name in POLICY["allowed_curves"]):
        raise Denied("key type not allowed")

    # 4. threshold of DISTINCT valid approvals
    valid = valid_approvers(request, approvals, registry)
    if len(valid) < M:
        raise Denied(f"only {len(valid)} valid distinct approvals, need {M}")

    # 5. single use
    con = sqlite3.connect(STATE_DB)
    con.execute("CREATE TABLE IF NOT EXISTS used(request_id TEXT PRIMARY KEY, ts REAL)")
    try:
        with con:
            con.execute("INSERT INTO used VALUES (?,?)", (request_id(request), time.time()))
    except sqlite3.IntegrityError:
        raise Denied("replay: this request was already used")
    finally:
        con.close()
    return csr, domains, hours, sorted(valid)

def authorize_and_sign(request, csr_pem, approvals) -> str:
    rid = request_id(request)
    try:
        csr, domains, hours, who = _check(request, csr_pem, approvals)
    except Denied as e:
        audit("DENIED", request_id=rid, reason=str(e))
        raise
    audit("AUTHORIZED", request_id=rid, approvers=who, domains=domains)
    return issue_leaf(csr, domains, hours)
