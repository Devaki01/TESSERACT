# TESSERACT

A zero-trust, HSM-backed Certificate Authority issuance pipeline with M-of-N
approval and ephemeral (24-72 hour) OCSP Must-Staple certificates.

**Case study:** the 2011 DigiNotar breach, in which attackers pivoted from public
web servers into the CA signing infrastructure and issued rogue certificates
(including `*.google.com`) that went undetected for weeks.

## What it demonstrates

| DigiNotar failure | TESSERACT control |
|---|---|
| CA signing key reachable from a compromised network | CA private keys are generated inside a PKCS#11 token and are non-extractable |
| One compromised system could issue any certificate | M-of-N (3 of 5) Ed25519 approvals, re-verified by the signer itself |
| Gateway or front-end compromise | The signer treats the gateway as untrusted and re-derives the domains from the CSR |
| Rogue issuance for domains nobody approved | Signer-side policy: allowed domains, no wildcards, 72h validity cap |
| Missing or tampered logs | Hash-chained audit log, including denied requests |
| Long-lived certificates and slow revocation | 24-72h certificates with the Must-Staple extension |

## Status

- [x] Phase 1: HSM-backed root and issuing CA (SoftHSM2 via PKCS#11)
- [x] Phase 2: M-of-N approval gateway, signer, attack tests
- [ ] Phase 2b: Shamir-split HSM PIN with a sealed/unsealed signer
- [ ] Phase 3: Network segmentation and mTLS between components
- [ ] Phase 4: ACME and automated renewal lifecycle manager
- [ ] Phase 5: OCSP responder, emergency revocation, hard-fail client, issuance monitor
- [ ] Phase 6: Attack simulation against a DigiNotar-style baseline

## Architecture

```
requester.py --> gateway.py --> signer.py --> HSM (issuing key, non-extractable)
                 (collects      (re-verifies everything,
approver.py ---> signatures)     then calls the HSM)
```

## Repository layout

```
ca_sign.py        builds root and intermediate certificates; the HSM does the signing
sign_leaf.py      standalone leaf issuance test (Phase 1)
extract_test.py   proves the issuing key cannot be read out of the token
env.sh            sets the PKCS#11 module path
certs/            public certificates, public keys and CSRs
mofn/
  common.py       canonical request format, signature verification helpers
  keygen.py       creates 5 approver Ed25519 keypairs and the public registry
  signer.py       policy checks, M-of-N verification, HSM signing, audit log
  gateway.py      HTTP service that collects approvals
  requester.py    CLI to submit a CSR and request issuance
  approver.py     CLI for an approver to review and sign a request
  attack_tests.py 10 automated attacks against the signer
```

No private keys are committed. See `.gitignore`. Every PIN in this project is a
lab-only value.

## Requirements

- Ubuntu on WSL2 or native Linux
- Python 3.10 or newer, OpenSSL 3.x
- SoftHSM2, OpenSC (`pkcs11-tool`)

```bash
sudo apt update
sudo apt install -y softhsm2 opensc openssl python3-venv python3-full \
                    python-is-python3 build-essential python3-dev libssl-dev git
```

## Setup

Keep the project in the Linux filesystem (`~/ca`), not under `/mnt/c`.

### 1. Python environment

```bash
cd ~/ca
python3 -m venv venv
source venv/bin/activate
pip install python-pkcs11 cryptography
```

### 2. SoftHSM configuration (two separate tokens)

```bash
mkdir -p ~/ca/root-hsm/tokens ~/ca/issuing-hsm/tokens ~/ca/certs

cat > ~/ca/root.conf <<EOT
directories.tokendir = $HOME/ca/root-hsm/tokens
objectstore.backend = file
log.level = ERROR
EOT

cat > ~/ca/issuing.conf <<EOT
directories.tokendir = $HOME/ca/issuing-hsm/tokens
objectstore.backend = file
log.level = ERROR
EOT

cat > ~/ca/env.sh <<'EOT'
export P11MOD=/usr/lib/softhsm/libsofthsm2.so
EOT
source ~/ca/env.sh
```

If `/usr/lib/softhsm/libsofthsm2.so` does not exist, find it with
`ls /usr/lib/*/softhsm/` and update `env.sh`.

### 3. Create the root and issuing keys inside the tokens

```bash
export SOFTHSM2_CONF=~/ca/root.conf
softhsm2-util --init-token --free --label rootCA --so-pin 11111111 --pin 1234
pkcs11-tool --module $P11MOD --token-label rootCA --login --pin 1234 \
  --keypairgen --key-type EC:secp384r1 --label root-key --id 01

export SOFTHSM2_CONF=~/ca/issuing.conf
softhsm2-util --init-token --free --label issuingCA --so-pin 22222222 --pin 5678
pkcs11-tool --module $P11MOD --token-label issuingCA --login --pin 5678 \
  --keypairgen --key-type EC:secp384r1 --label issuing-key --id 02
```

### 4. Export the public keys (public data only)

```bash
export SOFTHSM2_CONF=~/ca/root.conf
pkcs11-tool --module $P11MOD --token-label rootCA --login --pin 1234 \
  --read-object --type pubkey --label root-key -o certs/root_pub.der
openssl pkey -pubin -inform DER -in certs/root_pub.der -out certs/root_pub.pem

export SOFTHSM2_CONF=~/ca/issuing.conf
pkcs11-tool --module $P11MOD --token-label issuingCA --login --pin 5678 \
  --read-object --type pubkey --label issuing-key -o certs/issuing_pub.der
openssl pkey -pubin -inform DER -in certs/issuing_pub.der -out certs/issuing_pub.pem
```

### 5. Build the CA certificates (the HSM signs; keys never leave the token)

```bash
export SOFTHSM2_CONF=~/ca/root.conf
python ca_sign.py root
python ca_sign.py intermediate

openssl verify -CAfile certs/root.crt certs/root.crt
openssl verify -CAfile certs/root.crt certs/issuing.crt
```

Both must print `OK`. After this, the root token can be taken offline: encrypt
`root-hsm/`, store it off the machine, and delete it from the running system.

### 6. Create the approver keys (3-of-5)

```bash
cd ~/ca/mofn && mkdir -p keys && chmod 700 keys
python keygen.py
```

### 7. Create a test CSR

```bash
cd ~/ca
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout certs/leaf.key -subj "/CN=test.local" \
  -addext "subjectAltName=DNS:test.local" -out certs/leaf.csr
```

## Running the project

Open two terminals. Run this in both:

```bash
cd ~/ca && source env.sh && source venv/bin/activate
export SOFTHSM2_CONF=~/ca/issuing.conf HSM_PIN=5678
cd mofn
```

**Terminal 1:** start the gateway and leave it running.

```bash
python gateway.py
```

**Terminal 2:** submit a request and note the printed `request_id`.

```bash
python requester.py submit ../certs/leaf.csr 24 web1
RID=<the request_id, without angle brackets>
```

Try to issue before approval. It must be denied.

```bash
python requester.py issue $RID ../certs/test.crt
```

Approve as three different approvers. Each is shown the domains read from the CSR
itself and must type the first domain to confirm.

```bash
python approver.py approver1 $RID
python approver.py approver2 $RID
python approver.py approver3 $RID
```

Issue the certificate and verify it:

```bash
python requester.py issue $RID ../certs/test.crt
openssl verify -CAfile ../certs/root.crt -untrusted ../certs/issuing.crt ../certs/test.crt
openssl x509 -in ../certs/test.crt -noout -text | grep -E "Not After|status_request|DNS:"
```

Issuing the same request again is denied as a replay.

## Expected results

| Step | Result |
|---|---|
| Issue with 0 or 2 approvals | `403`, not enough valid distinct approvals |
| Issue with 3 approvals | Certificate written; `verify` says `OK` |
| Certificate contents | About 24h validity, `status_request` (Must-Staple), `DNS:test.local` |
| Issue the same request again | `403`, replay |

## Evidence tests

**Key non-extractability**

```bash
export SOFTHSM2_CONF=~/ca/issuing.conf
pkcs11-tool --module $P11MOD --token-label issuingCA --login --pin 5678 --list-objects
python ../extract_test.py
```

Expect `never extractable`, `EXTRACTABLE: False`, and a refused read of the key value.

**Attack suite** (simulates a fully compromised gateway)

```bash
cd ~/ca/mofn
python attack_tests.py
```

Expect `10/10 tests behaved as expected` and `audit chain intact: True`. The tests cover:

1. Legitimate 3-of-5 issuance succeeds
2. Replay of the same approvals
3. Only 2 approvals
4. One approver signing three times
5. Forged signatures
6. CSR swapped after approval
7. Request edited after approval (24h to 72h)
8. Expired request
9. Validity above the 72h cap
10. A domain outside policy (`google.com`), the DigiNotar scenario

**Audit log tamper test:** change one character in `mofn/audit.log`, then run
`python -c "import signer; print(signer.verify_audit())"`. It reports the broken line.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Connection refused` from the requester | Start `gateway.py` in Terminal 1 first |
| `KeyError: 'P11MOD'` or `'HSM_PIN'` | Run `source ~/ca/env.sh` and `export HSM_PIN=5678` |
| `NoSuchToken` | `SOFTHSM2_CONF` must point to the right config for that step |
| `ModuleNotFoundError: common` | Run the scripts from inside `~/ca/mofn` |
| Reruns report "replay" | Delete `mofn/signer_state.db` between demos |
| OpenSSL segfaults using `-provider pkcs11` | Known issue with the packaged provider. This project signs through Python PKCS#11 instead |
| `explicit ECC parameters` error | Known issue with the OpenSSL PKCS#11 engine. Same workaround |

## Limitations

- SoftHSM enforces non-extractability in software and gives no tamper resistance.
  A production deployment needs a real HSM (YubiHSM 2, Nitrokey HSM, or a cloud HSM).
- Approver keys are software keys. Production would use hardware tokens or WebAuthn.
- The gateway and signer currently run on one host. Phase 3 separates them with mTLS.
- A compromised signer host can still request signatures from the HSM. Phase 2b
  seals the PIN, and Phase 5 adds a monitor that flags certificates without approvals.
- Browsers do not consistently enforce OCSP Must-Staple. Short certificate lifetimes
  are the primary defense, and hard-fail Must-Staple is enforced only in a controlled client.

## License and disclaimer

Educational prototype built for a case-study project. Not for production use.
EOT
EOF
