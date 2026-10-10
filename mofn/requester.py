import sys
from pathlib import Path
from common import http_call

cmd = sys.argv[1] if len(sys.argv) > 1 else ""
if cmd == "submit":      # requester.py submit certs/leaf.csr 24 web1
    csr, hours, who = sys.argv[2], int(sys.argv[3]), sys.argv[4]
    code, r = http_call("POST", "/requests", {"csr_pem": Path(csr).read_text(),
                                              "validity_hours": hours, "requester": who})
    print(code, r)
elif cmd == "issue":     # requester.py issue <request_id> certs/leaf.crt
    code, r = http_call("POST", f"/requests/{sys.argv[2]}/issue")
    if code == 200:
        Path(sys.argv[3]).write_text(r["certificate"]); print("certificate written to", sys.argv[3])
    else:
        print(code, r)
else:
    sys.exit("usage: requester.py submit <csr> <hours> <name> | issue <id> <out.crt>")
