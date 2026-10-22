from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Literal, Optional

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.db import Database
from backend.policy import PolicyEngine
from backend.security import (
    KeyStore, PasswordService, SessionService, canonical_json, generate_totp_secret,
    otpauth_uri, utcnow, verify_totp
)

Decision = Literal["AUTO", "NOTIFY", "APPROVE", "DENY", "QUARANTINE"]
DOMAINS = Literal["financial", "health", "legal"]
BASE = Path(__file__).resolve().parents[1]
FRONTEND = BASE / "frontend"
DATA_DIR = Path(os.getenv("PTO_DATA_DIR", str(BASE / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_POLICY_PATH = BASE / "policies" / "default_policy.json"

class SetupRequest(BaseModel):
    setup_token: str
    display_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=12, max_length=256)

class SetupConfirm(BaseModel):
    code: str

class LoginRequest(BaseModel):
    email: str
    password: str
    code: str

class ActionIntent(BaseModel):
    principal_id: str = "principal-001"
    agent_id: str
    domain: DOMAINS
    action: str
    resource: Optional[str] = None
    counterparty: Optional[str] = None
    amount: Optional[float] = Field(default=None, ge=0)
    currency: Optional[str] = "USD"
    purpose: Optional[str] = None
    jurisdiction: str = "US-CA"
    data_classes: list[str] = []
    attributes: Dict[str, Any] = {}

class ApprovalDecision(BaseModel):
    decision: Literal["APPROVE", "DENY"]
    note: str = ""

class PolicyReplace(BaseModel):
    policy: Dict[str, Any]
    change_note: str = ""
    totp_code: Optional[str] = None

class VaultCreate(BaseModel):
    domain: DOMAINS
    label: str = Field(min_length=1, max_length=120)
    payload: Dict[str, Any]

class DelegationRequest(BaseModel):
    source_agent_id: str
    target_agent_id: str
    payload: Dict[str, Any]
    ttl_minutes: int = Field(default=60, ge=1, le=1440)

class CalendarAction(BaseModel):
    title: str
    start_iso: str
    end_iso: str
    location: str = ""
    description: str = ""

class EmailDraftAction(BaseModel):
    to: str
    subject: str
    body: str


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def create_app(database_url: Optional[str] = None, data_dir: Optional[Path] = None) -> FastAPI:
    ddir = data_dir or DATA_DIR
    ddir.mkdir(parents=True, exist_ok=True)
    db_url = database_url or os.getenv("DATABASE_URL", f"sqlite+pysqlite:///{ddir / 'pto_alpha_v0_1_1.db'}")
    db = Database(db_url)
    keys = KeyStore(ddir)
    passwords = PasswordService()
    sessions = SessionService(keys.session_secret)
    policy_engine = PolicyEngine()

    app = FastAPI(title="Turingsign PTO Alpha v0.1.1 — Principal #001 Operational Alpha", version="0.1.1")
    app.state.db = db
    app.state.keys = keys
    app.state.passwords = passwords
    app.state.sessions = sessions
    app.state.policy_engine = policy_engine
    app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")

    def principal_from_session(pto_session: Optional[str] = Cookie(default=None)) -> Dict[str, Any]:
        if not pto_session:
            raise HTTPException(401, "Authentication required")
        data = sessions.read(pto_session)
        if not data:
            raise HTTPException(401, "Session expired or invalid")
        row = db.one("SELECT * FROM principals WHERE principal_id=:p AND is_active=1", {"p": data["principal_id"]})
        if not row:
            raise HTTPException(401, "Principal inactive")
        return dict(row)

    def optional_principal(pto_session: Optional[str] = Cookie(default=None)) -> Optional[Dict[str, Any]]:
        if not pto_session:
            return None
        data = sessions.read(pto_session)
        if not data:
            return None
        row = db.one("SELECT * FROM principals WHERE principal_id=:p AND is_active=1", {"p": data["principal_id"]})
        return dict(row) if row else None

    def active_policy(principal_id: str) -> Dict[str, Any]:
        row = db.one("SELECT * FROM policy_versions WHERE principal_id=:p AND active=1 ORDER BY created_at DESC", {"p": principal_id})
        if not row:
            raise HTTPException(500, "No active Personal Authority Constitution")
        p = json.loads(row["policy_json"])
        p["_meta"] = {"policy_id": row["policy_id"], "version": row["version"], "policy_hash": row["policy_hash"]}
        return p

    def agent_status(agent_id: str, principal_id: str) -> Dict[str, Any]:
        a = db.one("SELECT * FROM agents WHERE agent_id=:a AND principal_id=:p", {"a": agent_id, "p": principal_id})
        if not a or a["status"] != "active":
            raise HTTPException(403, "Unknown, revoked, or unbound agent")
        cred = db.one("SELECT * FROM agent_credentials WHERE agent_id=:a AND revoked_at IS NULL ORDER BY issued_at DESC", {"a": agent_id})
        if not cred:
            raise HTTPException(403, "Agent has no active credential")
        if datetime.fromisoformat(cred["expires_at"]) <= datetime.now(timezone.utc):
            raise HTTPException(403, "Agent credential expired")
        return {"agent": dict(a), "credential": dict(cred)}

    def validate_agent_token(token: str) -> Dict[str, Any]:
        try:
            payload = keys.verify_agent_token(token)
        except Exception:
            raise HTTPException(401, "Invalid agent credential")
        if datetime.fromisoformat(payload["expires_at"]) <= datetime.now(timezone.utc):
            raise HTTPException(401, "Agent credential expired")
        row = db.one("SELECT * FROM agent_credentials WHERE credential_id=:c AND agent_id=:a", {"c": payload["credential_id"], "a": payload["agent_id"]})
        if not row or row["revoked_at"] is not None or row["token_hash"] != sha256_text(token):
            raise HTTPException(401, "Agent credential revoked or unknown")
        return payload

    def issue_agent_credential(agent_id: str, days: int = 30) -> Dict[str, Any]:
        agent = db.one("SELECT * FROM agents WHERE agent_id=:a", {"a": agent_id})
        if not agent:
            raise HTTPException(404, "Agent not found")
        now = datetime.now(timezone.utc)
        cred_id = f"cred-{uuid.uuid4()}"
        payload = {
            "credential_id": cred_id,
            "agent_id": agent_id,
            "principal_id": agent["principal_id"],
            "domain": agent["domain"],
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(days=days)).isoformat(),
            "issuer": "Turingsign PTO Alpha v0.1.1",
        }
        token = keys.issue_agent_token(payload)
        db.execute("INSERT INTO agent_credentials(credential_id,agent_id,token_hash,issued_at,expires_at,revoked_at) VALUES (:c,:a,:h,:i,:e,NULL)", {
            "c": cred_id, "a": agent_id, "h": sha256_text(token), "i": payload["issued_at"], "e": payload["expires_at"]
        })
        return {"token": token, **payload}

    def save_event(intent: Dict[str, Any], decision: str, reason: str, evidence: Dict[str, Any], status: str = "DECIDED", parent_event_id: Optional[str] = None, extra: Optional[Dict[str, Any]] = None):
        event_id = f"evt-{uuid.uuid4()}"
        p = active_policy(intent["principal_id"])
        body = {
            "event_id": event_id,
            "principal_id": intent["principal_id"],
            "agent_id": intent["agent_id"],
            "domain": intent["domain"],
            "action": intent["action"],
            "resource": intent.get("resource"),
            "counterparty": intent.get("counterparty"),
            "amount": intent.get("amount"),
            "currency": intent.get("currency"),
            "purpose": intent.get("purpose"),
            "jurisdiction": intent.get("jurisdiction", "US-CA"),
            "decision": decision,
            "decision_reason": reason,
            "policy_version": p["_meta"]["version"],
            "policy_hash": p["_meta"]["policy_hash"],
            "evidence": evidence,
            "parent_event_id": parent_event_id,
        }
        if extra:
            body.update(extra)
        signed = keys.sign_receipt(body)
        db.execute("""INSERT INTO trust_events(event_id,created_at,principal_id,agent_id,domain,action,decision,status,intent_json,receipt_json,parent_event_id)
                      VALUES (:e,:t,:p,:a,:d,:ac,:de,:s,:ij,:r,:pe)""", {
            "e": event_id, "t": utcnow(), "p": intent["principal_id"], "a": intent["agent_id"], "d": intent["domain"],
            "ac": intent["action"], "de": decision, "s": status, "ij": json.dumps(intent), "r": json.dumps(signed), "pe": parent_event_id
        })
        return event_id, signed

    def evaluate(intent: Dict[str, Any], principal: Optional[Dict[str, Any]], bearer: Optional[str]):
        if principal:
            if intent["principal_id"] != principal["principal_id"]:
                raise HTTPException(403, "Principal mismatch")
            st = agent_status(intent["agent_id"], principal["principal_id"])
            if st["agent"]["domain"] != intent["domain"]:
                raise HTTPException(403, "Agent domain mismatch")
            auth_evidence = {"channel": "principal_console", "credential_id": st["credential"]["credential_id"]}
        else:
            if not bearer or not bearer.startswith("Bearer "):
                raise HTTPException(401, "Principal session or Agent Bearer credential required")
            payload = validate_agent_token(bearer.split(" ", 1)[1])
            if payload["principal_id"] != intent["principal_id"] or payload["agent_id"] != intent["agent_id"] or payload["domain"] != intent["domain"]:
                raise HTTPException(403, "Credential does not bind this action intent")
            auth_evidence = {"channel": "agent_api", "credential_id": payload["credential_id"]}
        p = active_policy(intent["principal_id"])
        decision, reason, evidence = policy_engine.decide(p, intent)
        evidence = {**evidence, **auth_evidence}
        event_id, signed = save_event(intent, decision, reason, evidence, status="PENDING_APPROVAL" if decision == "APPROVE" else "DECIDED")
        approval_id = None
        if decision == "APPROVE":
            approval_id = f"appr-{uuid.uuid4()}"
            db.execute("INSERT INTO approvals(approval_id,event_id,principal_id,status,created_at) VALUES (:a,:e,:p,'PENDING',:t)", {
                "a": approval_id, "e": event_id, "p": intent["principal_id"], "t": utcnow()
            })
        return {"event_id": event_id, "decision": decision, "reason": reason, "approval_id": approval_id, "trust_receipt": signed}

    @app.get("/")
    def root():
        return FileResponse(FRONTEND / "index.html")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": "0.1.1", "environment": os.getenv("ENVIRONMENT", "US-CA-ALPHA")}

    @app.get("/v1/status")
    def status(principal: Optional[Dict[str, Any]] = Depends(optional_principal)):
        configured = bool(db.one("SELECT principal_id FROM principals WHERE is_active=1 LIMIT 1"))
        return {"configured": configured, "authenticated": bool(principal), "principal": {"principal_id": principal["principal_id"], "display_name": principal["display_name"], "email": principal["email"]} if principal else None}

    @app.post("/v1/setup")
    def setup(req: SetupRequest):
        if db.one("SELECT principal_id FROM principals LIMIT 1"):
            raise HTTPException(409, "PTO has already been initialized")
        expected = os.getenv("PTO_SETUP_TOKEN", "local-alpha-setup-change-me")
        if not secrets_compare(req.setup_token, expected):
            raise HTTPException(403, "Invalid setup token")
        try:
            password_hash = passwords.hash(req.password)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        secret = generate_totp_secret()
        db.execute("INSERT INTO principals(principal_id,display_name,email,password_hash,totp_secret,is_active,created_at) VALUES ('principal-001',:n,:e,:p,:s,0,:t)", {
            "n": req.display_name, "e": req.email.lower(), "p": password_hash, "s": secret, "t": utcnow()
        })
        return {"principal_id": "principal-001", "totp_secret": secret, "otpauth_uri": otpauth_uri(secret, req.email)}

    @app.post("/v1/setup/confirm")
    def setup_confirm(req: SetupConfirm):
        principal = db.one("SELECT * FROM principals WHERE principal_id='principal-001'")
        if not principal:
            raise HTTPException(404, "Run setup first")
        if principal["is_active"]:
            return {"status": "already-active"}
        if not verify_totp(principal["totp_secret"], req.code):
            raise HTTPException(400, "Invalid authenticator code")
        db.execute("UPDATE principals SET is_active=1 WHERE principal_id='principal-001'")
        for aid, domain, name in [
            ("financial-agent-001", "financial", "Financial Agent"),
            ("health-agent-001", "health", "Health Agent"),
            ("legal-agent-001", "legal", "Legal Agent"),
        ]:
            db.execute("INSERT INTO agents(agent_id,principal_id,domain,display_name,status,created_at) VALUES (:a,'principal-001',:d,:n,'active',:t)", {"a": aid, "d": domain, "n": name, "t": utcnow()})
            issue_agent_credential(aid)
        default = json.loads(DEFAULT_POLICY_PATH.read_text("utf-8"))
        default["principals"] = {"principal-001": {"display_name": principal["display_name"], "jurisdiction": "US-CA"}}
        default = policy_engine.enforce_guardrails(default)
        pjson = json.dumps(default, sort_keys=True)
        phash = sha256_text(pjson)
        pid = f"policy-{uuid.uuid4()}"
        acceptance = keys.sign_receipt({"type": "POLICY_ACCEPTANCE", "principal_id": "principal-001", "policy_hash": phash, "version": "PTO-US-CA-0.1.1-001", "authentication": "TOTP"})
        db.execute("""INSERT INTO policy_versions(policy_id,principal_id,version,policy_hash,policy_json,active,created_at,approved_at,change_note,acceptance_receipt_json)
                      VALUES (:id,'principal-001','PTO-US-CA-0.1.1-001',:h,:j,1,:t,:t,'Initial Principal #001 Constitution',:r)""", {
            "id": pid, "h": phash, "j": pjson, "t": utcnow(), "r": json.dumps(acceptance)
        })
        return {"status": "active", "principal_id": "principal-001", "policy_version": "PTO-US-CA-0.1.1-001"}

    @app.post("/v1/login")
    def login(req: LoginRequest, response: Response):
        principal = db.one("SELECT * FROM principals WHERE lower(email)=:e AND is_active=1", {"e": req.email.lower()})
        if not principal or not passwords.verify(principal["password_hash"], req.password) or not verify_totp(principal["totp_secret"], req.code):
            raise HTTPException(401, "Invalid login")
        token = sessions.create(principal["principal_id"])
        response.set_cookie("pto_session", token, httponly=True, samesite="strict", secure=os.getenv("PTO_SECURE_COOKIE", "0") == "1", max_age=8 * 3600)
        return {"status": "ok", "principal_id": principal["principal_id"]}

    @app.post("/v1/logout")
    def logout(response: Response):
        response.delete_cookie("pto_session")
        return {"status": "ok"}

    @app.get("/v1/config")
    def config(principal: Dict[str, Any] = Depends(principal_from_session)):
        p = active_policy(principal["principal_id"])
        return {
            "product": "Turingsign Personal Trust Office Alpha v0.1.1",
            "principal": {"principal_id": principal["principal_id"], "display_name": principal["display_name"]},
            "outcomes": ["AUTO", "NOTIFY", "APPROVE", "DENY", "QUARANTINE"],
            "policy": p,
            "guardrail": "US/California Alpha. No autonomous investment execution, diagnosis/medication change, or final legal advice.",
        }

    @app.get("/v1/agents")
    def agents(principal: Dict[str, Any] = Depends(principal_from_session)):
        rows = db.all("SELECT * FROM agents WHERE principal_id=:p ORDER BY domain", {"p": principal["principal_id"]})
        out = []
        for a in rows:
            cred = db.one("SELECT credential_id,issued_at,expires_at,revoked_at FROM agent_credentials WHERE agent_id=:a ORDER BY issued_at DESC LIMIT 1", {"a": a["agent_id"]})
            out.append({**a, "credential": dict(cred) if cred else None})
        return out

    @app.post("/v1/agents/{agent_id}/rotate")
    def rotate_agent(agent_id: str, principal: Dict[str, Any] = Depends(principal_from_session)):
        agent_status(agent_id, principal["principal_id"])
        db.execute("UPDATE agent_credentials SET revoked_at=:t WHERE agent_id=:a AND revoked_at IS NULL", {"t": utcnow(), "a": agent_id})
        return issue_agent_credential(agent_id)

    @app.post("/v1/agents/{agent_id}/revoke")
    def revoke_agent(agent_id: str, principal: Dict[str, Any] = Depends(principal_from_session)):
        agent_status(agent_id, principal["principal_id"])
        db.execute("UPDATE agent_credentials SET revoked_at=:t WHERE agent_id=:a AND revoked_at IS NULL", {"t": utcnow(), "a": agent_id})
        db.execute("UPDATE agents SET status='revoked' WHERE agent_id=:a", {"a": agent_id})
        return {"status": "revoked", "agent_id": agent_id}

    @app.post("/v1/action-intents")
    def action_intent(intent: ActionIntent, principal: Optional[Dict[str, Any]] = Depends(optional_principal), authorization: Optional[str] = Header(default=None)):
        return evaluate(intent.model_dump(), principal, authorization)

    @app.get("/v1/approvals")
    def approvals(principal: Dict[str, Any] = Depends(principal_from_session)):
        return db.all("""SELECT a.*, e.domain,e.action,e.agent_id,e.intent_json FROM approvals a JOIN trust_events e ON a.event_id=e.event_id
                         WHERE a.principal_id=:p ORDER BY a.created_at DESC LIMIT 100""", {"p": principal["principal_id"]})

    @app.post("/v1/approvals/{approval_id}")
    def approval_decision(approval_id: str, req: ApprovalDecision, principal: Dict[str, Any] = Depends(principal_from_session)):
        row = db.one("""SELECT a.*, e.intent_json FROM approvals a JOIN trust_events e ON a.event_id=e.event_id
                        WHERE a.approval_id=:a AND a.principal_id=:p""", {"a": approval_id, "p": principal["principal_id"]})
        if not row:
            raise HTTPException(404, "Approval not found")
        if row["status"] != "PENDING":
            raise HTTPException(409, "Approval already decided")
        intent = json.loads(row["intent_json"])
        final_decision = "AUTO" if req.decision == "APPROVE" else "DENY"
        reason = "Principal #001 explicitly approved exception" if req.decision == "APPROVE" else "Principal #001 denied exception"
        final_event_id, receipt = save_event(intent, final_decision, reason, {"human_approval": req.decision, "approval_id": approval_id, "note": req.note}, parent_event_id=row["event_id"])
        db.execute("UPDATE approvals SET status='DECIDED',decided_at=:t,decision=:d,note=:n,final_event_id=:f WHERE approval_id=:a", {
            "t": utcnow(), "d": req.decision, "n": req.note, "f": final_event_id, "a": approval_id
        })
        db.execute("UPDATE trust_events SET status='SUPERSEDED_BY_HUMAN' WHERE event_id=:e", {"e": row["event_id"]})
        return {"status": "DECIDED", "final_event_id": final_event_id, "decision": final_decision, "trust_receipt": receipt}

    @app.get("/v1/events")
    def events(limit: int = 50, principal: Dict[str, Any] = Depends(principal_from_session)):
        return db.all("SELECT event_id,created_at,agent_id,domain,action,decision,status,parent_event_id FROM trust_events WHERE principal_id=:p ORDER BY created_at DESC LIMIT :l", {"p": principal["principal_id"], "l": min(max(limit,1),200)})

    @app.get("/v1/events/{event_id}")
    def event(event_id: str, principal: Dict[str, Any] = Depends(principal_from_session)):
        row = db.one("SELECT * FROM trust_events WHERE event_id=:e AND principal_id=:p", {"e": event_id, "p": principal["principal_id"]})
        if not row:
            raise HTTPException(404, "Event not found")
        return {**dict(row), "intent": json.loads(row["intent_json"]), "trust_receipt": json.loads(row["receipt_json"])}

    @app.post("/v1/receipts/verify")
    def verify_receipt(payload: Dict[str, Any], principal: Dict[str, Any] = Depends(principal_from_session)):
        return {"valid": keys.verify_receipt(payload)}

    @app.get("/v1/policy")
    def get_policy(principal: Dict[str, Any] = Depends(principal_from_session)):
        return active_policy(principal["principal_id"])

    @app.post("/v1/policy")
    def replace_policy(req: PolicyReplace, principal: Dict[str, Any] = Depends(principal_from_session)):
        old = active_policy(principal["principal_id"])
        old.pop("_meta", None)
        proposed = policy_engine.enforce_guardrails(req.policy)
        reasons = policy_engine.expansion_reasons(old, proposed)
        if reasons:
            if not req.totp_code or not verify_totp(principal["totp_secret"], req.totp_code):
                raise HTTPException(403, {"message": "Authority expansion requires fresh Principal TOTP confirmation", "expansion_reasons": reasons})
        pjson = json.dumps(proposed, sort_keys=True)
        phash = sha256_text(pjson)
        count_row = db.one("SELECT COUNT(*) AS n FROM policy_versions WHERE principal_id=:p", {"p": principal["principal_id"]})
        version = f"PTO-US-CA-0.1.1-{int(count_row['n'])+1:03d}"
        acceptance = keys.sign_receipt({"type": "POLICY_ACCEPTANCE", "principal_id": principal["principal_id"], "policy_hash": phash, "version": version, "authentication": "SESSION+TOTP" if reasons else "SESSION", "authority_expansion": bool(reasons), "expansion_reasons": reasons})
        db.execute("UPDATE policy_versions SET active=0 WHERE principal_id=:p", {"p": principal["principal_id"]})
        db.execute("""INSERT INTO policy_versions(policy_id,principal_id,version,policy_hash,policy_json,active,created_at,approved_at,change_note,acceptance_receipt_json)
                      VALUES (:id,:p,:v,:h,:j,1,:t,:t,:n,:r)""", {
            "id": f"policy-{uuid.uuid4()}", "p": principal["principal_id"], "v": version, "h": phash, "j": pjson,
            "t": utcnow(), "n": req.change_note, "r": json.dumps(acceptance)
        })
        return {"version": version, "policy_hash": phash, "authority_expansion": bool(reasons), "expansion_reasons": reasons, "acceptance_receipt": acceptance}

    @app.get("/v1/policy/history")
    def policy_history(principal: Dict[str, Any] = Depends(principal_from_session)):
        return db.all("SELECT policy_id,version,policy_hash,active,created_at,approved_at,change_note FROM policy_versions WHERE principal_id=:p ORDER BY created_at DESC", {"p": principal["principal_id"]})

    @app.post("/v1/vault")
    def vault_create(req: VaultCreate, principal: Dict[str, Any] = Depends(principal_from_session)):
        item_id = f"vault-{uuid.uuid4()}"
        aad = f"{principal['principal_id']}|{req.domain}|{item_id}"
        enc = keys.encrypt_vault(req.payload, aad)
        db.execute("INSERT INTO vault_items(item_id,principal_id,domain,label,nonce,ciphertext,created_at) VALUES (:i,:p,:d,:l,:n,:c,:t)", {
            "i": item_id, "p": principal["principal_id"], "d": req.domain, "l": req.label, "n": enc["nonce"], "c": enc["ciphertext"], "t": utcnow()
        })
        return {"item_id": item_id, "domain": req.domain, "label": req.label, "encrypted": True}

    @app.get("/v1/vault")
    def vault_list(principal: Dict[str, Any] = Depends(principal_from_session)):
        return db.all("SELECT item_id,domain,label,created_at FROM vault_items WHERE principal_id=:p ORDER BY created_at DESC", {"p": principal["principal_id"]})

    @app.get("/v1/vault/{item_id}")
    def vault_get(item_id: str, principal: Dict[str, Any] = Depends(principal_from_session)):
        row = db.one("SELECT * FROM vault_items WHERE item_id=:i AND principal_id=:p", {"i": item_id, "p": principal["principal_id"]})
        if not row:
            raise HTTPException(404, "Vault item not found")
        aad = f"{principal['principal_id']}|{row['domain']}|{row['item_id']}"
        return {"item_id": row["item_id"], "domain": row["domain"], "label": row["label"], "payload": keys.decrypt_vault(row["nonce"], row["ciphertext"], aad)}

    @app.post("/v1/delegations")
    def delegation(req: DelegationRequest, principal: Dict[str, Any] = Depends(principal_from_session)):
        src = agent_status(req.source_agent_id, principal["principal_id"])["agent"]
        tgt = agent_status(req.target_agent_id, principal["principal_id"])["agent"]
        if src["domain"] == tgt["domain"]:
            raise HTTPException(400, "Cross-domain delegation expected")
        p = active_policy(principal["principal_id"])
        minimized = policy_engine.minimize(p, src["domain"], tgt["domain"], req.payload)
        delegation_id = f"dlg-{uuid.uuid4()}"
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=req.ttl_minutes)).isoformat()
        assertion = {
            "delegation_id": delegation_id,
            "principal_id": principal["principal_id"],
            "source_agent_id": src["agent_id"],
            "target_agent_id": tgt["agent_id"],
            "source_domain": src["domain"],
            "target_domain": tgt["domain"],
            "purpose_bound": True,
            "disclosed": minimized,
            "withheld_field_count": max(0, len(req.payload)-len(minimized)),
            "policy_version": p["_meta"]["version"],
            "expires_at": expires_at,
        }
        receipt = keys.sign_receipt({"type": "MINIMUM_DISCLOSURE_DELEGATION", **assertion})
        db.execute("""INSERT INTO delegations(delegation_id,principal_id,source_agent_id,target_agent_id,source_domain,target_domain,created_at,expires_at,assertion_json,receipt_json)
                      VALUES (:i,:p,:s,:t,:sd,:td,:c,:e,:a,:r)""", {
            "i": delegation_id, "p": principal["principal_id"], "s": src["agent_id"], "t": tgt["agent_id"], "sd": src["domain"], "td": tgt["domain"],
            "c": utcnow(), "e": expires_at, "a": json.dumps(assertion), "r": json.dumps(receipt)
        })
        return {"assertion": assertion, "trust_receipt": receipt}

    @app.post("/v1/operational/calendar")
    def operational_calendar(req: CalendarAction, principal: Dict[str, Any] = Depends(principal_from_session)):
        intent = ActionIntent(agent_id="health-agent-001", domain="health", action="schedule_appointment", purpose="Prepare user-controlled calendar event").model_dump()
        result = evaluate(intent, principal, None)
        if result["decision"] not in ("AUTO", "NOTIFY"):
            return result
        ics = make_ics(req)
        result["ics"] = ics
        return result

    @app.post("/v1/operational/email-draft")
    def operational_email(req: EmailDraftAction, principal: Dict[str, Any] = Depends(principal_from_session)):
        intent = ActionIntent(agent_id="legal-agent-001", domain="legal", action="draft_response", counterparty=req.to, purpose="Prepare user-controlled email draft").model_dump()
        result = evaluate(intent, principal, None)
        if result["decision"] not in ("AUTO", "NOTIFY"):
            return result
        msg = EmailMessage()
        msg["To"] = req.to
        msg["Subject"] = req.subject
        msg.set_content(req.body)
        result["eml"] = msg.as_string()
        return result

    return app


def secrets_compare(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


def make_ics(req: CalendarAction) -> str:
    def fmt(v: str) -> str:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    uid = f"{uuid.uuid4()}@turingsign-alpha"
    safe = lambda s: s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")
    return "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Turingsign//PTO Alpha v0.1.1//EN", "BEGIN:VEVENT",
        f"UID:{uid}", f"DTSTAMP:{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}", f"DTSTART:{fmt(req.start_iso)}", f"DTEND:{fmt(req.end_iso)}",
        f"SUMMARY:{safe(req.title)}", f"LOCATION:{safe(req.location)}", f"DESCRIPTION:{safe(req.description)}", "END:VEVENT", "END:VCALENDAR", ""
    ])

app = create_app()
