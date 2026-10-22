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

def test_invited_user_isolation(tmp_path):
    c, app = client(tmp_path)
    admin_secret = activate(c, app)
    invite = c.post('/v1/principals/invitations', json={"email":"user2@example.com","totp_code":totp_now(admin_secret)})
    assert invite.status_code == 200
    token = invite.json()["invitation_token"]
    new = c.post('/v1/principals/register', json={"token":token,"display_name":"Principal Two","password":"LongEnoughSecondPassword!"})
    assert new.status_code == 200
    pid = new.json()["principal_id"]
    assert pid != "principal-001"
    assert c.post('/v1/principals/register', json={"token":token,"display_name":"Again","password":"LongEnoughSecondPassword!"}).status_code == 403
    assert c.post('/v1/principals/register/confirm',json={"token":token,"code":totp_now(new.json()["totp_secret"])}).status_code == 200
    own = c.post('/v1/vault', json={"domain":"financial","label":"private","payload":{"secret":"admin-only"}})
    assert own.status_code == 200
    admin_item = own.json()["item_id"]
    c.post('/v1/logout')
    assert c.post('/v1/login',json={"email":"user2@example.com","password":"LongEnoughSecondPassword!","code":totp_now(new.json()["totp_secret"])}).status_code == 200
    assert c.get('/v1/vault').json() == []
    assert c.get(f'/v1/vault/{admin_item}').status_code == 404
    assert c.get('/v1/events').json() == []
    assert c.get('/v1/approvals').json() == []
    assert c.get('/v1/policy').status_code == 200
    agents = c.get('/v1/agents').json()
    assert len(agents) == 3 and all(a["principal_id"] == pid for a in agents)
    own_action = c.post('/v1/action-intents',json={"principal_id":pid,"agent_id":agents[0]["agent_id"],"domain":agents[0]["domain"],"action":"organize_records"})
    assert own_action.status_code == 200
    cross = c.post('/v1/action-intents',json={"principal_id":"principal-001","agent_id":"financial-agent-001","domain":"financial","action":"analyze_accounts"})
    assert cross.status_code == 403
    assert c.post('/v1/principals/invitations',json={"email":"user3@example.com","totp_code":totp_now(new.json()["totp_secret"])}).status_code == 403
