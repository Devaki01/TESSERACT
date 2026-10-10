import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from common import build_request, request_id, valid_approvers, load_registry
import signer

STORE = {}   # in-memory; fine for the prototype

class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        print("[gateway]", fmt % a)

    def reply(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        p = self.path.strip("/").split("/")
        if len(p) == 2 and p[0] == "requests" and p[1] in STORE:
            rec = STORE[p[1]]
            return self.reply(200, {**rec, "approval_count": len(rec["approvals"])})
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        p = self.path.strip("/").split("/")
        b = self.body()
        if p == ["requests"]:
            try:
                req = build_request(b["csr_pem"].encode(), int(b.get("validity_hours", 24)),
                                    b.get("requester", "unknown"))
            except Exception as e:
                return self.reply(400, {"error": f"bad request: {e}"})
            rid = request_id(req)
            STORE[rid] = {"request": req, "csr_pem": b["csr_pem"], "approvals": []}
            return self.reply(201, {"request_id": rid})
        if len(p) == 3 and p[0] == "requests" and p[1] in STORE:
            rec = STORE[p[1]]
            if p[2] == "approve":
                a = {"approver_id": b.get("approver_id"), "signature": b.get("signature")}
                if not valid_approvers(rec["request"], [a], load_registry()):
                    return self.reply(403, {"error": "bad signature or unknown approver"})
                rec["approvals"] = [x for x in rec["approvals"]
                                    if x["approver_id"] != a["approver_id"]] + [a]
                return self.reply(200, {"approval_count": len(rec["approvals"])})
            if p[2] == "issue":
                try:
                    cert = signer.authorize_and_sign(rec["request"], rec["csr_pem"].encode(),
                                                     rec["approvals"])
                except signer.Denied as e:
                    return self.reply(403, {"error": str(e)})
                return self.reply(200, {"certificate": cert})
        self.reply(404, {"error": "not found"})

if __name__ == "__main__":
    print("gateway on http://127.0.0.1:8080")
    ThreadingHTTPServer(("127.0.0.1", 8080), H).serve_forever()
