# API Quickstart — External Agent Channel

The browser dashboard uses an authenticated Principal session. A separately hosted AI agent can instead present a Turingsign Agent Credential as a Bearer token.

## Obtain a credential
From the Principal dashboard, rotate the desired agent credential. The newly issued token is shown once in the response pane. Treat it as a secret.

## Submit an Action Intent

```bash
curl -s http://localhost:8000/v1/action-intents \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $PTO_AGENT_TOKEN" \
  -d '{
    "principal_id":"principal-001",
    "agent_id":"financial-agent-001",
    "domain":"financial",
    "action":"pay_recurring_bill",
    "amount":125,
    "currency":"USD",
    "jurisdiction":"US-CA",
    "attributes":{"approved_payee":true}
  }'
```

The credential binds `agent_id`, `principal_id`, `domain`, issue time and expiry. The server also checks revocation state before the request reaches the policy engine.

## Decision semantics
- `AUTO`: the action is inside currently delegated authority.
- `NOTIFY`: it may proceed without blocking, but the Principal should be informed.
- `APPROVE`: it is blocked pending an explicit Principal decision in the Approval Inbox.
- `DENY`: the active policy or hard guardrail forbids the action.
- `QUARANTINE`: identity/credential/trust validation failed.
