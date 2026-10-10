#!/usr/bin/env python3
"""Build CA certificates where the HSM (PKCS#11) does the signing.
Usage: SOFTHSM2_CONF=~/ca/root.conf python ca_sign.py root
       SOFTHSM2_CONF=~/ca/root.conf python ca_sign.py intermediate
"""
import sys, os, datetime, hashlib
import pkcs11
from pkcs11 import Mechanism, ObjectClass
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

MODULE = os.environ.get("P11MOD", "/usr/lib/softhsm/libsofthsm2.so")
ROOT_TOKEN, ROOT_PIN, ROOT_KEY = "rootCA", "1234", "root-key"

def der(tag, content):
    n = len(content)
    if n < 128:   l = bytes([n])
    elif n < 256: l = b"\x81" + bytes([n])
    else:         l = b"\x82" + n.to_bytes(2, "big")
    return bytes([tag]) + l + content

# DER of AlgorithmIdentifier { ecdsa-with-SHA384 }
SIG_ALG = bytes.fromhex("300a06082a8648ce3d040303")

def hsm_sign(token_label, pin, key_label, data):
    lib = pkcs11.lib(MODULE)
    token = lib.get_token(token_label=token_label)
    with token.open(user_pin=pin) as s:
        priv = s.get_key(label=key_label, object_class=ObjectClass.PRIVATE_KEY)
        raw = priv.sign(hashlib.sha384(data).digest(), mechanism=Mechanism.ECDSA)
    h = len(raw) // 2
    return encode_dss_signature(int.from_bytes(raw[:h], "big"),
                                int.from_bytes(raw[h:], "big"))

def load_pub(path):
    return serialization.load_pem_public_key(open(path, "rb").read())

def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DemoCA"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])

def build_and_sign(subject, subject_pub, issuer, issuer_pub, days, pathlen):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer)
         .public_key(subject_pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
              key_encipherment=False, data_encipherment=False, key_agreement=False,
              key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
              critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_pub), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub),
                        critical=False))
    # Throwaway key only to get a well-formed TBS; its signature is discarded.
    dummy = b.sign(ec.generate_private_key(ec.SECP384R1()), hashes.SHA384())
    tbs = dummy.tbs_certificate_bytes
    sig = hsm_sign(ROOT_TOKEN, ROOT_PIN, ROOT_KEY, tbs)      # real signature from the HSM
    cert_der = der(0x30, tbs + SIG_ALG + der(0x03, b"\x00" + sig))
    return x509.load_der_x509_certificate(cert_der)

mode = sys.argv[1] if len(sys.argv) > 1 else ""
if mode == "root":
    pub = load_pub("certs/root_pub.pem")
    cert = build_and_sign(name("Demo Root CA"), pub, name("Demo Root CA"), pub, 3650, 1)
    out = "certs/root.crt"
elif mode == "intermediate":
    root_pub = load_pub("certs/root_pub.pem")
    iss_pub = load_pub("certs/issuing_pub.pem")
    cert = build_and_sign(name("Demo Issuing CA"), iss_pub, name("Demo Root CA"),
                          root_pub, 1825, 0)
    out = "certs/issuing.crt"
else:
    sys.exit("usage: ca_sign.py root|intermediate")

open(out, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
print("wrote", out)
