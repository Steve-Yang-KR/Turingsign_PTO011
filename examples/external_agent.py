"""Example external-agent call using a one-time-visible Agent Credential token.

1) Sign in to PTO Alpha and rotate an agent credential.
2) Copy the returned token into PTO_AGENT_TOKEN.
3) Run this file against your local Alpha.
"""
import json, os, urllib.request

base = os.getenv("PTO_BASE_URL", "http://localhost:8000")
token = os.environ["PTO_AGENT_TOKEN"]
intent = {
    "principal_id": "principal-001",
    "agent_id": "financial-agent-001",
    "domain": "financial",
    "action": "pay_recurring_bill",
    "amount": 125,
    "currency": "USD",
    "jurisdiction": "US-CA",
    "attributes": {"approved_payee": True},
}
req = urllib.request.Request(
    base + "/v1/action-intents",
    data=json.dumps(intent).encode(),
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    method="POST",
)
with urllib.request.urlopen(req) as r:
    print(json.dumps(json.load(r), indent=2))
