import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_INJECTION_PATH = Path("/data/honeypot/injections.json")
TRACE_RISK_LEVEL = "pending"


def injection_path() -> Path:
    return Path(os.environ.get(
        "HONEYPOT_INJECTION_PATH",
        os.environ.get("DEMO_INJECTION_POLICY_PATH", str(DEFAULT_INJECTION_PATH)),
    ))


def _read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def load_trace_policies() -> dict[str, dict]:
    payload = _read_json(injection_path())
    policies = payload.get("policies", {}) if isinstance(payload, dict) else {}
    return {
        session_id: policy
        for session_id, policy in policies.items()
        if isinstance(policy, dict)
        and policy.get("state") == "engaged"
        and policy.get("beacon")
        and policy.get("mode") in (None, "trace")
    }


def create_trace_policy(session_id: str, source_ip: str) -> dict:
    path = injection_path()
    payload = _read_json(path)
    policies = payload.setdefault("policies", {})
    existing = policies.get(session_id)
    if isinstance(existing, dict) and existing.get("beacon"):
        return existing

    timestamp = datetime.now(timezone.utc).isoformat()
    policy = {
        "countermeasure_id": f"cm_{datetime.now().strftime('%Y%m%d')}_{secrets.token_hex(3)}",
        "session_id": session_id,
        "source_ip": source_ip,
        "beacon": f"cmz_{secrets.token_hex(3)}",
        "mode": "trace",
        "state": "engaged",
        "mimic_profile": "trace_agent",
        "risk_level": TRACE_RISK_LEVEL,
        "trigger": {
            "verdict": "pending",
            "confidence": 0,
            "reason": "会话进入蜜罐后默认启用溯源诱饵",
            "source": "session_bootstrap",
        },
        "created_at": timestamp,
    }
    policies[session_id] = policy
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return policy
