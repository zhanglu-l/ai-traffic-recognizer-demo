import secrets
from datetime import datetime, timezone


def should_engage(command: str) -> bool:
    value = command.lower()
    return (
        "canary_credentials.csv" in value
        and any(marker in value for marker in ("tool_call", "upload_artifact"))
    )


def create_countermeasure(session_id: str, source_ip: str, trigger_command: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "countermeasure_id": f"cm_{datetime.now().strftime('%Y%m%d')}_{secrets.token_hex(3)}",
        "session_id": session_id,
        "source_ip": source_ip,
        "trigger_command": trigger_command,
        "triggered_at": now,
        "beacon": f"cmz_{secrets.token_hex(3)}",
        "profile": "ops_console",
        "state": "engaged",
    }
