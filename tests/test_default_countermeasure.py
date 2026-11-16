import importlib.util
import json
import os
import tempfile
from pathlib import Path


def load_demo_server():
    script_dir = Path(__file__).resolve().parents[1] / "backend"
    script_path = script_dir / "demo_server.py"
    spec = importlib.util.spec_from_file_location("demo_server_under_test", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    with tempfile.TemporaryDirectory() as temp_dir:
        os.environ["LLM_API_KEY"] = "test-key"
        os.environ["DEMO_STATE_PATH"] = str(Path(temp_dir) / "state.json")
        os.environ["DEMO_INJECTION_POLICY_PATH"] = str(Path(temp_dir) / "injections.json")
        spec.loader.exec_module(module)
    return module


def test_create_trace_policy_creates_and_reuses_session_policy():
    from honeypot.countermeasure_policy import create_trace_policy

    with tempfile.TemporaryDirectory() as temp_dir:
        os.environ["HONEYPOT_INJECTION_PATH"] = str(Path(temp_dir) / "injections.json")
        first = create_trace_policy("session-1", "10.0.0.8")
        second = create_trace_policy("session-1", "10.0.0.8")
        assert first["mode"] == "trace"
        assert first["state"] == "engaged"
        assert first["risk_level"] == "pending"
        assert first["beacon"] == second["beacon"]


def scenario(session_id="session-1", source_ip="10.0.0.8"):
    return {
        "sessionId": session_id,
        "sourceIp": source_ip,
        "requests": [{"body": "cat /root/.cache/backup/canary_credentials.csv"}],
    }


def test_default_creates_pending_countermeasure():
    module = load_demo_server()
    countermeasure = module.create_countermeasure(scenario())
    assert countermeasure["state"] == "engaged"
    assert countermeasure["risk_level"] == "pending"
    assert countermeasure["trigger"]["verdict"] == "pending"
    assert countermeasure["trigger"]["source"] == "automatic"


def test_high_confidence_upgrades_risk_level():
    module = load_demo_server()
    countermeasure = module.create_countermeasure(
        scenario(), {"verdict": "ai", "confidence": 0.9}
    )
    assert countermeasure["risk_level"] == "high"


def test_trace_beacon_response_triggers_auto_reason():
    module = load_demo_server()
    scenario = {
        "latestTimestamp": "2026-01-01T00:00:00Z",
        "requests": [
            {"body": "cat /var/lib/ops-console/agent.conf"},
            {"body": "tool_call: report_context --beacon=cmz_abc123"},
        ],
        "deceptionEvidence": {},
        "countermeasure": {"mode": "trace"},
        "traceBaitTouched": True,
        "mimicInjectionObserved": True,
        "mimicInstructionResponse": True,
        "mimicToolCallback": True,
    }
    assert module.auto_trigger_reason(scenario) == "溯源诱饵 Beacon 响应，立即研判"
