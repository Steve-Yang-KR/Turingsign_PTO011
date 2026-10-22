# Security Notes — PTO Alpha v0.1.1

This is a **private operational Alpha**, not a production security appliance.

## Implemented
- Argon2 password hashing.
- TOTP MFA for sign-in.
- Fresh TOTP challenge before detected authority expansion.
- HttpOnly, SameSite=Strict session cookie.
- Persistent Ed25519 signing keys for Trust Receipts and Agent Credentials.
- Credential expiry, rotation and revocation.
- AES-256-GCM encryption for local vault payloads.
- Fail-to-human-approval for unknown actions.
- Hard DENY guardrails for investment execution, medication change, and final legal advice.
- Append-style Trust Event records and signed receipts.
- Purpose-bound minimum-disclosure delegation.

## Not production-ready
- Local filesystem keys are not HSM/KMS protected.
- No rate limiting / WAF / intrusion monitoring.
- No external identity proofing or recovery workflow.
- No hardware-backed passkey/WebAuthn yet.
- No formal immutable/WORM ledger.
- No data-loss prevention engine beyond configured disclosure fields.
- No formal HIPAA, GLBA, SEC/FINRA, legal-services, CCPA/CPRA or SOC 2 compliance attestation.

## Before public Beta
1. Move signing and vault keys to managed KMS/HSM.
2. Add passkeys/WebAuthn and tested account recovery.
3. Put behind TLS with secure cookies and reverse-proxy hardening.
4. Add CSRF defense, rate limits, structured security logs and alerting.
5. Separate application, audit, key and sensitive-data stores.
6. Complete threat model, dependency scan, SAST/DAST and penetration test.
7. Review data-processing roles and regulated-domain scope with counsel.
