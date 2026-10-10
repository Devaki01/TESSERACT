import os, pkcs11
from pkcs11 import Attribute, ObjectClass
lib = pkcs11.lib(os.environ["P11MOD"])
tok = lib.get_token(token_label="issuingCA")
with tok.open(user_pin="5678") as s:
    k = s.get_key(label="issuing-key", object_class=ObjectClass.PRIVATE_KEY)
    print("EXTRACTABLE:", k[Attribute.EXTRACTABLE], " SENSITIVE:", k[Attribute.SENSITIVE])
    try:
        print("VALUE:", k[Attribute.VALUE])
    except Exception as e:
        print("Direct read of key bytes REFUSED by token:", type(e).__name__)
