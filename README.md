# Turingsign Personal Trust Office Alpha v0.1.1 — Principal #001 Operational Alpha

**Primary site:** Bay Area / California, USA  
**Primary principal:** Principal #001  
**Agents:** Financial + Health + Legal  
**Status:** Operational Alpha package for private testing; not production or regulated professional service.

## What changed from v0.1

v0.1.1 turns the frozen Trust Kernel into a Principal-operated Alpha:

- first-run Principal #001 onboarding
- Argon2 password + TOTP MFA and signed session cookie
- versioned Personal Authority Constitution
- fresh-TOTP requirement for any authority expansion
- three durable Agent Credentials with expiry, rotation and revocation
- Approval Inbox for exception actions
- persistent Ed25519 Trust Receipt signing key
- encrypted local Personal Vault (AES-256-GCM)
- signed minimum-disclosure Health → Financial delegation
- Trust Receipt/event history
- low-risk operational connectors: downloadable `.ics` calendar event and `.eml` email draft
- API channel for external agents using Bearer Agent Credentials

## Security invariant

> The system may learn or recommend a policy change, but it cannot silently enlarge its own authority. Any detected expansion requires fresh Principal MFA confirmation. Hard Alpha guardrails cannot be removed through policy editing.

## Run with Docker

1. Copy `.env.example` to `.env` and set a long random `PTO_SETUP_TOKEN`.
2. Run:

```bash
docker compose up --build
```

3. Open <http://localhost:8000>.
4. Initialize Principal #001. Add the displayed TOTP secret to an authenticator app and confirm it.
5. Sign in and begin with synthetic/low-risk data only.

## Run locally without Docker

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
export PYTHONPATH=.
export PTO_SETUP_TOKEN='replace-me'
uvicorn backend.main:app --reload
```

## Tests

```bash
PYTHONPATH=. pytest -q
```

## Alpha boundaries

Do **not** use this build for:

- brokerage/trading execution or custody of funds
- autonomous diagnosis, medication, treatment, or emergency decisions
- final legal advice or attorney impersonation
- storing production secrets/credentials or large volumes of sensitive records
- public internet exposure without HTTPS, reverse proxy controls, rate limiting, monitoring and security review

See `docs/PRINCIPAL_001_RUNBOOK.md` and `SECURITY.md`.
