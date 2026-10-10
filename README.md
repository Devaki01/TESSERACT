# TESSERACT
Zero-trust, HSM-backed CA issuance pipeline with M-of-N approval and
ephemeral (24-72h) Must-Staple certificates. Case study: the DigiNotar breach.

## Status
- Phase 1: HSM-backed root + issuing CA (SoftHSM2 / PKCS#11)
- Phase 2: M-of-N approval gateway and signer (Ed25519)

## Security notes
All PINs in this repo are lab-only values. No private keys are committed;
see .gitignore. Production would use a real HSM and hardware-token approvers.
