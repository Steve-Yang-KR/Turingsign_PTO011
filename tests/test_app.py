import os
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.security import totp_now


def client(tmp_path: Path):
    os.environ["PTO_SETUP_TOKEN"]="test-setup-token"
    app=create_app(f"sqlite+pysqlite:///{tmp_path/'test.db'}", tmp_path/"data")
    return TestClient(app), app


def activate(c, app):
    r=c.post('/v1/setup',json={"setup_token":"test-setup-token","display_name":"Principal #001","email":"p@example.com","password":"LongEnoughPassword!"}); assert r.status_code==200
    secret=r.json()['totp_secret']
    r=c.post('/v1/setup/confirm',json={"code":totp_now(secret)}); assert r.status_code==200
    r=c.post('/v1/login',json={"email":"p@example.com","password":"LongEnoughPassword!","code":totp_now(secret)}); assert r.status_code==200
    return secret


def test_operational_flow(tmp_path):
    c, app=client(tmp_path); secret=activate(c,app)
    r=c.post('/v1/action-intents',json={"principal_id":"principal-001","agent_id":"financial-agent-001","domain":"financial","action":"pay_new_beneficiary","amount":700,"attributes":{}})
    assert r.status_code==200 and r.json()['decision']=='APPROVE'
    aid=r.json()['approval_id']
    r=c.post(f'/v1/approvals/{aid}',json={"decision":"APPROVE","note":"test"}); assert r.status_code==200 and r.json()['decision']=='AUTO'
    rows=c.get('/v1/events').json(); assert len(rows)>=2


def test_policy_expansion_requires_totp(tmp_path):
    c, app=client(tmp_path); secret=activate(c,app)
    p=c.get('/v1/policy').json(); p.pop('_meta',None); p['rules']['financial']['pay_recurring_bill']['approve_above']=1000
    r=c.post('/v1/policy',json={"policy":p,"change_note":"expand"}); assert r.status_code==403
    r=c.post('/v1/policy',json={"policy":p,"change_note":"expand","totp_code":totp_now(secret)}); assert r.status_code==200


def test_delegation_withholds_sensitive_fields(tmp_path):
    c, app=client(tmp_path); activate(c,app)
    r=c.post('/v1/delegations',json={"source_agent_id":"health-agent-001","target_agent_id":"financial-agent-001","payload":{"provider":"X","amount":10,"currency":"USD","diagnosis":"secret"},"ttl_minutes":60})
    data=r.json()['assertion']['disclosed']; assert 'provider' in data and 'diagnosis' not in data
