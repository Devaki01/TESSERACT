import sys, time
from common import (BASE, http_call, request_id, csr_digest, csr_domains, sign_request)

if len(sys.argv) != 3:
    sys.exit("usage: approver.py <approver_id> <request_id>")
aid, rid = sys.argv[1], sys.argv[2]
key_pem = (BASE / "keys" / f"{aid}.key").read_bytes()

code, rec = http_call("GET", f"/requests/{rid}")
if code != 200:
    sys.exit(f"gateway error: {rec}")
req, csr_pem = rec["request"], rec["csr_pem"].encode()

# Independent verification: do NOT trust the gateway's description of the request.
if request_id(req) != rid:
    sys.exit("REFUSED: request body does not match its id")
real = csr_domains(csr_pem)
if csr_digest(csr_pem) != req["csr_sha256"] or real != req["domains"]:
    sys.exit("REFUSED: CSR does not match the request. Gateway may be compromised!")
if not real:
    sys.exit("REFUSED: CSR has no DNS names")

print("\n=== ISSUANCE REQUEST (domains below were read from the CSR itself) ===")
print("domains   :", ", ".join(real))
print("validity  :", req["validity_hours"], "hours")
print("requester :", req["requester"])
print("expires in:", int(req["expires_at"] - time.time()), "seconds")
ans = input(f"\nType the first domain ({real[0]}) to APPROVE, anything else rejects: ").strip()
if ans != real[0]:
    sys.exit("rejected, nothing signed")

code, r = http_call("POST", f"/requests/{rid}/approve",
                    {"approver_id": aid, "signature": sign_request(req, key_pem)})
print(code, r)
