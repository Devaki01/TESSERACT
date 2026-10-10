import sys, os, datetime, hashlib, pkcs11
from pkcs11 import Mechanism, ObjectClass
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

def der(tag, c):
    n = len(c)
    l = bytes([n]) if n < 128 else (b"\x81"+bytes([n]) if n < 256 else b"\x82"+n.to_bytes(2,"big"))
    return bytes([tag]) + l + c
SIG_ALG = bytes.fromhex("300a06082a8648ce3d040303")

def hsm_sign(data):
    lib = pkcs11.lib(os.environ["P11MOD"])
    tok = lib.get_token(token_label="issuingCA")
    with tok.open(user_pin="5678") as s:
        k = s.get_key(label="issuing-key", object_class=ObjectClass.PRIVATE_KEY)
        raw = k.sign(hashlib.sha384(data).digest(), mechanism=Mechanism.ECDSA)
    h = len(raw)//2
    return encode_dss_signature(int.from_bytes(raw[:h],"big"), int.from_bytes(raw[h:],"big"))

hours = int(sys.argv[1]) if len(sys.argv) > 1 else 72
csr = x509.load_pem_x509_csr(open("certs/leaf.csr","rb").read())
assert csr.is_signature_valid
issuer = x509.load_pem_x509_certificate(open("certs/issuing.crt","rb").read())
iss_pub = serialization.load_pem_public_key(open("certs/issuing_pub.pem","rb").read())
san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
now = datetime.datetime.now(datetime.timezone.utc)
b = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(issuer.subject)
     .public_key(csr.public_key()).serial_number(x509.random_serial_number())
     .not_valid_before(now - datetime.timedelta(minutes=5))
     .not_valid_after(now + datetime.timedelta(hours=hours))
     .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
     .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False), critical=True)
     .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
     .add_extension(san, critical=False)
     .add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False)
     .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(iss_pub), critical=False))
tbs = b.sign(ec.generate_private_key(ec.SECP384R1()), hashes.SHA384()).tbs_certificate_bytes
cert = x509.load_der_x509_certificate(der(0x30, tbs + SIG_ALG + der(0x03, b"\x00" + hsm_sign(tbs))))
open("certs/leaf.crt","wb").write(cert.public_bytes(serialization.Encoding.PEM))
print("issued, valid until", cert.not_valid_after_utc)
