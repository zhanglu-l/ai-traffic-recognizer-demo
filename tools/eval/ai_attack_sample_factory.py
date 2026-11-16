#!/usr/bin/env python3
import argparse
import json
import random
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EVAL_SESSIONS_PATH = ROOT / "samples" / "eval_sessions.jsonl"
RAW_DIR = ROOT / "samples" / "raw"

def iso_at(base_ts: int, step: int) -> str:
    from datetime import datetime, timezone
    value = datetime.fromtimestamp(base_ts + step, timezone.utc).isoformat().replace("+00:00", "Z")
    return value


def ai_sample(profile: dict, seed: int, ts: int) -> dict:
    rng = random.Random(seed)
    profile = dict(profile)
    profile["commands"] = list(profile["commands"])
    tags = set(profile["tags"])
    if "bait" in tags:
        profile["commands"] = profile["commands"] + [
            "cat /root/.cache/backup/canary_credentials.csv",
        ]
    if "induced_tool" in tags:
        profile["commands"] = profile["commands"] + [
            "tool_call: upload_artifact /root/.cache/backup/canary_credentials.csv",
        ]
    if "mimic" in tags:
        profile["commands"] = profile["commands"] + [
            "find /opt /data -maxdepth 3 -type f -print",
            "cat /opt/ops-console/agent.conf",
            "tool_call: report_context --beacon=cmz_eval_" + f"{seed:04x}",
        ]

    events = [{"step": 1, "timestamp": iso_at(ts, 0), "action": "SSH auth", "status": 200, "params": "root / admin123456"}]
    for index, command in enumerate(profile["commands"], 2):
        gap = rng.uniform(0.7, 1.6)
        ts += gap
        events.append({
            "step": index,
            "timestamp": iso_at(ts, 0),
            "action": "exec:" + command.split(" ", 1)[0].lstrip("/"),
            "status": 0,
            "params": command,
        })
    return {
        "sample_id": f"ssh-eval-ai-{seed:04d}",
        "created_at": events[0]["timestamp"],
        "honeypot": "ssh",
        "label": "ai-agent",
        "family": profile["family"],
        "task": profile["task"],
        "expected_verdict": "ai",
        "executed": True,
        "events": events,
        "client": {"user_agent": profile["user_agent"], "tls_fingerprint": profile["tls_fingerprint"]},
        "source_ip": "10.244." + str(100 + (seed % 100)) + ".17",
        "artifact_paths": {"sensor": f"ssh-eval-ai-{seed:04d}.events.jsonl"},
        "tags": sorted(tags),
    }


AI_PROFILES = [
    {"family": "minimal_recon", "task": "执行最小化主机侦察，只输出事实", "user_agent": "claude-code", "tls_fingerprint": "agent_claude", "commands": ["whoami", "uname -a", "cat /etc/os-release"], "tags": ["bait_free", "short_chain"]},
    {"family": "system_audit", "task": "审计 SSH 服务配置和登录策略", "user_agent": "codex_cli", "tls_fingerprint": "agent_codex", "commands": ["cat /etc/ssh/sshd_config", "last -a -F -n 50", "lastlog"], "tags": ["bait_free"]},
    {"family": "agent_hunt", "task": "寻找遗留的 AI Agent 配置", "user_agent": "openai-codex", "tls_fingerprint": "agent_openai", "commands": ["find /root /home /opt -type f \\( -name AGENTS.md -o -name .mcp.json -o -name agent.conf \\) -print", "cat AGENTS.md", "cat .mcp.json"], "tags": ["bait_free"]},
    {"family": "code_review", "task": "检查部署脚本中的凭据泄露", "user_agent": "cursor-agent", "tls_fingerprint": "agent_cursor", "commands": ["grep -RInE 'api[_-]?key|secret|password|token' /opt /data --exclude='*.log'", "sed -n '1,160p' /opt/app/config.py"], "tags": ["bait_free"]},
    {"family": "lateral_probe", "task": "检查内网可达服务与共享凭据", "user_agent": "opencode", "tls_fingerprint": "agent_opencode", "commands": ["cat /etc/hosts", "ss -tulpn", "find /root -name '*.env' -o -name 'id_rsa'"], "tags": ["bait_free"]},
    {"family": "database_recon", "task": "定位数据库配置和备份", "user_agent": "aider", "tls_fingerprint": "agent_aider", "commands": ["find /opt /data -type f \\( -name '*.sql' -o -name 'database.yml' -o -name 'db.conf' \\)", "cat /etc/my.cnf"], "tags": ["bait_free"]},
    {"family": "minimal_recon", "task": "读取备份目录并评估凭据价值", "user_agent": "claude-code", "tls_fingerprint": "agent_claude", "commands": ["ls -la /root/.cache/backup"], "tags": ["bait", "partial"]},
    {"family": "credential_harvest", "task": "解析可复用凭据，准备下一步横向移动", "user_agent": "codex_cli", "tls_fingerprint": "agent_codex", "commands": ["grep -RInE 'password|token|secret' /root /opt /data"], "tags": ["bait_free"]},
    {"family": "decoy_followthrough", "task": "根据备份文件内容完成上传", "user_agent": "opencode", "tls_fingerprint": "agent_opencode", "commands": ["ls -la /root/.cache/backup"], "tags": ["bait", "induced_tool"]},
    {"family": "mimic_followthrough", "task": "同步待处理的业务文件", "user_agent": "cursor-agent", "tls_fingerprint": "agent_cursor", "commands": ["find /opt /data -maxdepth 3 -type f -print"], "tags": ["mimic"]},
]


def scanner_sample(profile: dict, seed: int, ts: int) -> dict:
    rng = random.Random(seed)
    events = [{"step": 1, "timestamp": iso_at(ts, 0), "action": "SSH auth", "status": 200, "params": "root / admin123456"}]
    for index, command in enumerate(profile["commands"], 2):
        ts += rng.uniform(0.08, 0.35)
        events.append({"step": index, "timestamp": iso_at(ts, 0), "action": "exec:" + command.split(" ", 1)[0], "status": 0, "params": command})
    return {
        "sample_id": f"ssh-eval-scanner-{seed:04d}", "created_at": events[0]["timestamp"], "honeypot": "ssh",
        "label": "automated-scanner", "family": profile["family"], "task": profile["task"],
        "expected_verdict": "human", "executed": True, "events": events,
        "client": {"user_agent": profile["user_agent"], "tls_fingerprint": profile["tls_fingerprint"]},
        "source_ip": "10.244." + str(100 + (seed % 100)) + ".17",
        "artifact_paths": {"sensor": f"ssh-eval-scanner-{seed:04d}.events.jsonl"}, "tags": ["hard_negative"],
    }


SCANNER_PROFILES = [
    {"family": "metasploit_scanner", "task": "自动化后渗透枚举", "user_agent": "meterpreter", "tls_fingerprint": "msf_shell", "commands": ["uname -a", "id", "cat /etc/passwd", "ss -tulpn", "find / -name '*config*' -type f 2>/dev/null | head -100", "crontab -l", "cat /proc/net/route", "arp -a", "netstat -rn"]},
    {"family": "legacy_worm", "task": "批量主机指纹和常用弱配置检查", "user_agent": "Go-http-client/1.1", "tls_fingerprint": "unknown", "commands": ["cat /etc/issue", "ps auxww | grep -E 'sshd|nginx|mysql|redis'", "ls /etc/init.d", "cat /etc/crontab", "find /tmp /var/tmp -type f -perm -o+x | head -100", "curl --version"]},
    {"family": "ci_runner", "task": "部署后的批量一致性检查", "user_agent": "ci-runner", "tls_fingerprint": "automation", "commands": ["hostname", "cat /etc/os-release", "systemctl is-active sshd", "df -h", "systemctl list-unit-files | grep enabled", "grep -R 'TODO' /opt/app | head -100"]},
]


def human_sample(profile: dict, seed: int, ts: int) -> dict:
    rng = random.Random(seed)
    events = [{"step": 1, "timestamp": iso_at(ts, 0), "action": "SSH auth", "status": 200, "params": "root / admin123456"}]
    for index, command in enumerate(profile["commands"], 2):
        ts += rng.uniform(6, 35)
        if rng.random() < 0.2:
            ts += rng.uniform(2, 10)
        events.append({"step": index, "timestamp": iso_at(ts, 0), "action": "exec:" + command.split(" ", 1)[0], "status": 0, "params": command})
    return {
        "sample_id": f"ssh-eval-human-{seed:04d}", "created_at": events[0]["timestamp"], "honeypot": "ssh",
        "label": profile["label"], "family": profile["family"], "task": profile["task"],
        "expected_verdict": "human", "executed": True, "events": events,
        "client": {"user_agent": profile["user_agent"], "tls_fingerprint": profile["tls_fingerprint"]},
        "source_ip": "10.244." + str(100 + (seed % 100)) + ".17",
        "artifact_paths": {"sensor": f"ssh-eval-human-{seed:04d}.events.jsonl"},
        "tags": profile.get("tags", []),
    }


HUMAN_PROFILES = [
    {"family": "routine_ops", "task": "例行巡检", "user_agent": "ssh-client", "tls_fingerprint": "ssh", "commands": ["uptime", "df -h", "systemctl status nginx --no-pager"], "label": "human"},
    {"family": "incident_response", "task": "排查登录告警", "user_agent": "openssh-client", "tls_fingerprint": "ssh", "commands": ["last -a", "who -a", "ausearch -m USER_LOGIN --start today", "grep sshd /var/log/auth.log | tail -50"], "label": "human"},
    {"family": "human_attacker", "task": "人工尝试读取备份凭据，但未调用工具", "user_agent": "Pentoo/ssh", "tls_fingerprint": "ssh", "commands": ["ls -la /root", "cat /etc/passwd", "cat /root/.cache/backup/canary_credentials.csv", "grep password /root/.cache/backup/*.csv"], "label": "human-attacker", "tags": ["bait", "hard_negative"]},
]


def sensor_path(sample_id: str) -> Path:
    return RAW_DIR / f"{sample_id}.events.jsonl"


def write_sensor(sample: dict) -> None:
    session_id = sample["sample_id"]
    source_ip = "10.244." + str(100 + (int(sample["sample_id"].split('-')[-1], 16) % 100)) + ".17"
    username, password = "root", "admin123456"
    rows = []
    for event in sample["events"]:
        rows.append({"sample_id": session_id, "events": [{
            "from_ip": source_ip, "from_port": 40000 + event["step"], "to_ip": "10.244.0.7", "to_port": 22,
            "timestamp": iso_to_epoch(event["timestamp"]), "urlpath": "/api/event/report", "uuid": session_id,
            "type": {"name": "Password Login Event", "en": "Password Login Event", "value": "password_login"},
            "data": {"username": {"value": username}, "password": {"value": password}, "success": {"value": "yes"}},
            "risk_level": "high"}]})
        if event.get("action", "").startswith("exec:"):
            command = event["params"]
            rows[-1]["events"].append({
                "from_ip": source_ip, "from_port": 40000 + event["step"], "to_ip": "10.244.0.7", "to_port": 22,
                "timestamp": iso_to_epoch(event["timestamp"]) + 0.1, "urlpath": "/api/event/report", "uuid": session_id,
                "type": {"name": "Shell Command Execution", "en": "Shell Command Execution", "value": "shell_command"},
                "data": {"command": {"value": command}}, "risk_level": "high"})
    sensor_path(session_id).write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")


def iso_to_epoch(value: str) -> float:
    from datetime import datetime, timezone
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def build_suite(per_family: int) -> list[dict]:
    base_ts = int(time.time()) - 86400
    samples = []
    seed = 1
    for profile in AI_PROFILES:
        for _ in range(per_family):
            samples.append(ai_sample(profile, seed, base_ts + seed * 3600)); seed += 1
    for profile in SCANNER_PROFILES:
        for _ in range(per_family):
            samples.append(scanner_sample(profile, seed, base_ts + seed * 3600)); seed += 1
    for profile in HUMAN_PROFILES:
        for _ in range(per_family):
            samples.append(human_sample(profile, seed, base_ts + seed * 3600)); seed += 1
    for sample in samples:
        write_sensor(sample)
    return samples


def main() -> None:
    parser = argparse.ArgumentParser(description="生成贴近线上的 AI/扫描器/人工 SSH 评测样本")
    parser.add_argument("--per-family", type=int, default=8, help="每个 family 生成多少个变体")
    parser.add_argument("--dry-run", action="store_true", help="只输出统计，不写入文件")
    args = parser.parse_args()
    if args.dry_run:
        from collections import Counter
        planned = [
            profile["family"] for profile in AI_PROFILES for _ in range(args.per_family)
        ] + [
            profile["family"] for profile in SCANNER_PROFILES for _ in range(args.per_family)
        ] + [
            profile["family"] for profile in HUMAN_PROFILES for _ in range(args.per_family)
        ]
        print("planned families:", Counter(planned))
    else:
        samples = build_suite(args.per_family)
        existing_eval = [
            json.loads(line) for line in EVAL_SESSIONS_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ] if EVAL_SESSIONS_PATH.exists() else []
        retained_eval = [row for row in existing_eval if not row.get("sample_id", "").startswith("ssh-eval-")]
        EVAL_SESSIONS_PATH.write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in retained_eval + samples) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {len(samples)} samples to {EVAL_SESSIONS_PATH}")


if __name__ == "__main__":
    main()
