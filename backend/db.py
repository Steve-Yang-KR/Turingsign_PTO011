from __future__ import annotations
import json
from typing import Any, Dict, Iterable, Optional
from sqlalchemy import create_engine, text

SCHEMA = [
"""CREATE TABLE IF NOT EXISTS principals (
 principal_id VARCHAR(128) PRIMARY KEY,
 display_name VARCHAR(255) NOT NULL,
 email VARCHAR(255),
 password_hash TEXT NOT NULL,
 totp_secret VARCHAR(128) NOT NULL,
 is_active INTEGER NOT NULL DEFAULT 0,
 created_at VARCHAR(64) NOT NULL
)""",
"""CREATE TABLE IF NOT EXISTS agents (
 agent_id VARCHAR(128) PRIMARY KEY,
 principal_id VARCHAR(128) NOT NULL,
 domain VARCHAR(32) NOT NULL,
 display_name VARCHAR(255) NOT NULL,
 status VARCHAR(32) NOT NULL,
 created_at VARCHAR(64) NOT NULL
)""",
"""CREATE TABLE IF NOT EXISTS agent_credentials (
 credential_id VARCHAR(128) PRIMARY KEY,
 agent_id VARCHAR(128) NOT NULL,
 token_hash VARCHAR(128) NOT NULL,
 issued_at VARCHAR(64) NOT NULL,
 expires_at VARCHAR(64) NOT NULL,
 revoked_at VARCHAR(64)
)""",
"""CREATE TABLE IF NOT EXISTS policy_versions (
 policy_id VARCHAR(128) PRIMARY KEY,
 principal_id VARCHAR(128) NOT NULL,
 version VARCHAR(128) NOT NULL,
 policy_hash VARCHAR(128) NOT NULL,
 policy_json TEXT NOT NULL,
 active INTEGER NOT NULL,
 created_at VARCHAR(64) NOT NULL,
 approved_at VARCHAR(64) NOT NULL,
 change_note TEXT,
 acceptance_receipt_json TEXT
)""",
"""CREATE TABLE IF NOT EXISTS trust_events (
 event_id VARCHAR(128) PRIMARY KEY,
 created_at VARCHAR(64) NOT NULL,
 principal_id VARCHAR(128) NOT NULL,
 agent_id VARCHAR(128) NOT NULL,
 domain VARCHAR(32) NOT NULL,
 action VARCHAR(128) NOT NULL,
 decision VARCHAR(32) NOT NULL,
 status VARCHAR(32) NOT NULL,
 intent_json TEXT NOT NULL,
 receipt_json TEXT NOT NULL,
 parent_event_id VARCHAR(128)
)""",
"""CREATE TABLE IF NOT EXISTS approvals (
 approval_id VARCHAR(128) PRIMARY KEY,
 event_id VARCHAR(128) NOT NULL,
 principal_id VARCHAR(128) NOT NULL,
 status VARCHAR(32) NOT NULL,
 created_at VARCHAR(64) NOT NULL,
 decided_at VARCHAR(64),
 decision VARCHAR(32),
 note TEXT,
 final_event_id VARCHAR(128)
)""",
"""CREATE TABLE IF NOT EXISTS vault_items (
 item_id VARCHAR(128) PRIMARY KEY,
 principal_id VARCHAR(128) NOT NULL,
 domain VARCHAR(32) NOT NULL,
 label VARCHAR(255) NOT NULL,
 nonce VARCHAR(64) NOT NULL,
 ciphertext TEXT NOT NULL,
 created_at VARCHAR(64) NOT NULL
)""",
"""CREATE TABLE IF NOT EXISTS delegations (
 delegation_id VARCHAR(128) PRIMARY KEY,
 principal_id VARCHAR(128) NOT NULL,
 source_agent_id VARCHAR(128) NOT NULL,
 target_agent_id VARCHAR(128) NOT NULL,
 source_domain VARCHAR(32) NOT NULL,
 target_domain VARCHAR(32) NOT NULL,
 created_at VARCHAR(64) NOT NULL,
 expires_at VARCHAR(64) NOT NULL,
 assertion_json TEXT NOT NULL,
 receipt_json TEXT NOT NULL
)""",
"""CREATE TABLE IF NOT EXISTS principal_invitations (
 invite_id VARCHAR(128) PRIMARY KEY,
 email VARCHAR(255) NOT NULL,
 token_hash VARCHAR(128) NOT NULL UNIQUE,
 invited_by VARCHAR(128) NOT NULL,
 expires_at VARCHAR(64) NOT NULL,
 created_at VARCHAR(64) NOT NULL,
 claimed_principal_id VARCHAR(128)
)""",
"""CREATE TABLE IF NOT EXISTS approved_signup_emails (
 email VARCHAR(255) PRIMARY KEY,
 approved_by VARCHAR(128) NOT NULL,
 approved_at VARCHAR(64) NOT NULL,
 claimed_principal_id VARCHAR(128)
)""",
"""CREATE TABLE IF NOT EXISTS email_otp (
 challenge_id VARCHAR(128) PRIMARY KEY,
 email VARCHAR(255) NOT NULL,
 purpose VARCHAR(32) NOT NULL,
 code_hash VARCHAR(128) NOT NULL,
 expires_at VARCHAR(64) NOT NULL,
 created_at VARCHAR(64) NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 consumed_at VARCHAR(64)
)""",
]

class Database:
    def __init__(self, url: str):
        self.engine = create_engine(url, future=True)
        with self.engine.begin() as conn:
            for stmt in SCHEMA:
                conn.execute(text(stmt))

    def one(self, sql: str, params: Optional[Dict[str, Any]] = None):
        with self.engine.begin() as conn:
            return conn.execute(text(sql), params or {}).mappings().first()

    def all(self, sql: str, params: Optional[Dict[str, Any]] = None):
        with self.engine.begin() as conn:
            return [dict(r) for r in conn.execute(text(sql), params or {}).mappings().all()]

    def execute(self, sql: str, params: Optional[Dict[str, Any]] = None):
        with self.engine.begin() as conn:
            conn.execute(text(sql), params or {})
