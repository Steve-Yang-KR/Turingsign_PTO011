from backend.policy import PolicyEngine


def base_policy():
    return {
        "rules": {
            "financial": {
                "pay_recurring_bill": {"default": "NOTIFY", "approve_above": 500, "deny_above": 10000, "required_attributes": ["approved_payee"]},
                "execute_investment": {"default": "DENY"},
            },
            "health": {"medication_change": {"default": "DENY"}},
            "legal": {"legal_advice": {"default": "DENY"}},
        },
        "minimum_disclosure": {"health->financial": ["provider", "amount"]},
    }


def test_normal_bill_notifies():
    e=PolicyEngine(); d,_,_=e.decide(base_policy(), {"domain":"financial","action":"pay_recurring_bill","amount":420,"attributes":{"approved_payee":True}})
    assert d=="NOTIFY"


def test_large_bill_approves():
    e=PolicyEngine(); d,_,_=e.decide(base_policy(), {"domain":"financial","action":"pay_recurring_bill","amount":700,"attributes":{"approved_payee":True}})
    assert d=="APPROVE"


def test_hard_guardrail_cannot_be_weakened():
    e=PolicyEngine(); p=base_policy(); p["rules"]["financial"]["execute_investment"]["default"]="AUTO"
    guarded=e.enforce_guardrails(p)
    d,_,_=e.decide(guarded,{"domain":"financial","action":"execute_investment","amount":1,"attributes":{}})
    assert d=="DENY"


def test_minimum_disclosure():
    e=PolicyEngine(); out=e.minimize(base_policy(),"health","financial",{"provider":"X","amount":10,"diagnosis":"secret"})
    assert out=={"provider":"X","amount":10}


def test_expansion_detection():
    e=PolicyEngine(); old=base_policy(); new=base_policy(); new["rules"]["financial"]["pay_recurring_bill"]["approve_above"]=1000
    assert e.expansion_reasons(old,new)
