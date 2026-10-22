from __future__ import annotations
from copy import deepcopy
from typing import Any, Dict, Tuple

HARD_DENY = {
    ("financial", "execute_investment"): "Alpha never executes securities transactions",
    ("health", "medication_change"): "Clinical treatment decisions are outside Alpha authority",
    ("legal", "legal_advice"): "Alpha does not provide final legal advice",
}
RANK = {"DENY": 0, "APPROVE": 1, "NOTIFY": 2, "AUTO": 3}

class PolicyEngine:
    def decide(self, policy: Dict[str, Any], intent: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        domain = intent.get("domain")
        action = intent.get("action")
        if (domain, action) in HARD_DENY:
            return "DENY", HARD_DENY[(domain, action)], {"hard_guardrail": True}

        rule = policy.get("rules", {}).get(domain, {}).get(action)
        if not rule:
            return "APPROVE", "No explicit rule; fail closed to human approval", {}

        amount = intent.get("amount")
        if amount is not None:
            if rule.get("deny_above") is not None and amount > float(rule["deny_above"]):
                return "DENY", f"Amount exceeds deny threshold {rule['deny_above']}", {"rule": rule}
            if rule.get("approve_above") is not None and amount > float(rule["approve_above"]):
                return "APPROVE", f"Amount exceeds autonomous threshold {rule['approve_above']}", {"rule": rule}

        required = set(rule.get("required_attributes", []))
        attrs = set((intent.get("attributes") or {}).keys())
        missing = sorted(required - attrs)
        if missing:
            return "APPROVE", f"Missing required attributes: {', '.join(missing)}", {"rule": rule}

        outcome = rule.get("default", "APPROVE")
        return outcome, rule.get("reason", "Policy matched"), {"rule": rule}

    def minimize(self, policy: Dict[str, Any], source_domain: str, target_domain: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        key = f"{source_domain}->{target_domain}"
        fields = policy.get("minimum_disclosure", {}).get(key, [])
        return {k: payload[k] for k in fields if k in payload}

    def expansion_reasons(self, old: Dict[str, Any], new: Dict[str, Any]) -> list[str]:
        reasons: list[str] = []
        old_rules = old.get("rules", {})
        new_rules = new.get("rules", {})
        for domain, actions in new_rules.items():
            for action, nr in actions.items():
                if (domain, action) in HARD_DENY and nr.get("default") != "DENY":
                    reasons.append(f"{domain}.{action} attempts to weaken a hard guardrail")
                    continue
                orule = old_rules.get(domain, {}).get(action)
                if not orule:
                    if RANK.get(nr.get("default", "APPROVE"), 1) > RANK["APPROVE"]:
                        reasons.append(f"new autonomous authority: {domain}.{action}")
                    continue
                if RANK.get(nr.get("default", "APPROVE"), 1) > RANK.get(orule.get("default", "APPROVE"), 1):
                    reasons.append(f"default authority expanded for {domain}.{action}")
                oa, na = orule.get("approve_above"), nr.get("approve_above")
                if oa is not None and (na is None or float(na) > float(oa)):
                    reasons.append(f"approval threshold expanded for {domain}.{action}")
                od, nd = orule.get("deny_above"), nr.get("deny_above")
                if od is not None and (nd is None or float(nd) > float(od)):
                    reasons.append(f"deny threshold expanded for {domain}.{action}")
                old_req, new_req = set(orule.get("required_attributes", [])), set(nr.get("required_attributes", []))
                if old_req - new_req:
                    reasons.append(f"required attributes removed for {domain}.{action}")
        return reasons

    def enforce_guardrails(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        p = deepcopy(policy)
        for (domain, action), reason in HARD_DENY.items():
            p.setdefault("rules", {}).setdefault(domain, {}).setdefault(action, {})
            p["rules"][domain][action].update({"default": "DENY", "reason": reason})
            p["rules"][domain][action].pop("approve_above", None)
            p["rules"][domain][action].pop("deny_above", None)
        return p
