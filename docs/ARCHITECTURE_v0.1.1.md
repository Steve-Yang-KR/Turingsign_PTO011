# PTO Alpha v0.1.1 Architecture Freeze

## Canonical flow

```text
Principal #001 / External Agent
        |
        v
Action Intent + Agent Credential
        |
        v
Identity / Credential Gate
        |
        v
Active Personal Authority Constitution
        |
        v
Hard Guardrails + Policy Decision
        |
        +--> AUTO
        +--> NOTIFY
        +--> APPROVE --> Approval Inbox --> Principal explicit decision
        +--> DENY
        +--> QUARANTINE
        |
        v
Minimum-Disclosure Gateway (when cross-agent)
        |
        v
Low-risk Operational Connector / Simulation
        |
        v
Persistent Ed25519 Trust Receipt + Event History
```

## Patent-relevant implementation hooks retained
1. **Cross-Domain Authority Firewall** — domain-specific agents operate under one principal authority graph while protected data remains separated.
2. **Minimum-Disclosure Agent Delegation** — source-to-target agent assertion is purpose-bound and contains only policy-selected fields.
3. **Multi-Agent Trust Receipt** — receipt binds principal, agents, policy hash/version, decision, delegation/action evidence and time.
4. **Non-Expanding Authority Learning** — policy can be narrowed without extra friction; detected expansion requires fresh principal authentication and a signed acceptance receipt.
5. **Future Jurisdiction Resolver** — `jurisdiction` is already a first-class Action Intent field; v0.1.1 fixes the runtime to US-CA while preserving the extension point.
