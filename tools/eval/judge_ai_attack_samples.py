#!/usr/bin/env python3
import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import json as jsonlib
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from backend.feature_extraction import score_command_composition
BAITS_PATH = ROOT / "honeypot" / "decoys.json"
DEFAULT_SESSIONS_PATH = ROOT / "samples" / "eval_sessions.jsonl"


def read_jsonl(path: Path) -> list[dict]:
    return [jsonlib.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_baits() -> list[dict]:
    return jsonlib.loads(BAITS_PATH.read_text(encoding="utf-8")).get("baits", [])


def evaluate_baits(actions: list[str], baits: list[dict]) -> dict:
    evidence = {"fakeDataTouched": False, "toolExecutionObserved": False, "matchedBaits": []}
    for action in actions:
        lowered = action.lower()
        for bait in baits:
            touched = bait.get("path", "").lower() in lowered or bait.get("displayName", "").lower() in lowered
            executed = bait.get("successCommand", "").lower() in lowered and touched
            if touched:
                evidence["fakeDataTouched"] = True
                if bait.get("id") not in evidence["matchedBaits"]:
                    evidence["matchedBaits"].append(bait.get("id"))
            if executed:
                evidence["toolExecutionObserved"] = True
    return evidence


def build_evidence(sample: dict, baits: list[dict]) -> dict:
    events = sample.get("events", [])
    client = sample.get("client", {})
    commands = [item.get("params", "") for item in events if item.get("action", "").startswith("exec:")]
    timestamps = [item.get("timestamp", "") for item in events if item.get("timestamp")]
    intervals = []
    for current, next_value in zip(timestamps, timestamps[1:]):
        try:
            current_time = datetime.fromisoformat(current.replace("Z", "+00:00")).timestamp()
            next_time = datetime.fromisoformat(next_value.replace("Z", "+00:00")).timestamp()
            intervals.append(round(next_time - current_time, 3))
        except (ValueError, TypeError):
            continue
    deception = evaluate_baits(commands, baits)
    command_composition = score_command_composition(commands)
    return {
        "scenario": {
            "key": f"eval_ssh_{sample.get('sample_id')}",
            "sourceIp": sample.get("source_ip"),
            "sessionId": sample.get("sample_id"),
            "sampleId": sample.get("sample_id"),
            "family": sample.get("family"),
            "task": sample.get("task"),
            "sourceKind": sample.get("label"),
        },
        "protocol": "ssh",
        "window": "session",
        "client": {
            "userAgent": client.get("user_agent", "ssh-client"),
            "userAgentStatus": "UNKNOWN" if not client.get("user_agent") else "MATCHED",
            "alpn": client.get("tls_fingerprint", "ssh"),
            "alpnStatus": "UNKNOWN" if not client.get("tls_fingerprint") else "MATCHED",
        },
        "behavior": {
            "timing": {"status": "OBSERVED" if len(commands) >= 3 else "SAMPLE_INSUFFICIENT", "intervals": intervals},
            "toolChain": {"status": "OBSERVED" if any("tool_call" in command.lower() for command in commands) else "UNKNOWN", "signals": []},
            "attackChain": {"status": "OBSERVED", "stages": ["login", "shell"]},
            "payload": {"status": "UNKNOWN", "signals": []},
            "commandComposition": command_composition,
        },
        "session": {
            "sourceIp": sample.get("source_ip"),
            "requestCount": len(events),
            "commands": commands,
            "breadth": len(set(commands)),
        },
        "timing": {"intervals": intervals},
        "deception": deception,
        "decisionPolicy": {
            "ruleLayerRole": "feature_extraction_and_aggregation",
            "llmLayerRole": "final_scoring_and_verdict",
        },
    }


def evidence_payload(sample: dict, baits: list[dict]) -> dict:
    evidence = build_evidence(sample, baits)
    return {"scenario": evidence["scenario"], "evidence": evidence}


def call_llm(payload: dict) -> dict:
    from backend import demo_server
    judged = demo_server.judge_llm_payload(payload)
    return judged["llmResponse"]


def local_signal_verdict(scenario: dict) -> tuple[str, float]:
    commands = [command.lower() for command in scenario["session"]["commands"]]
    intervals = scenario["timing"]["intervals"]
    medium_intervals = [value for value in intervals if 0.3 <= value <= 3.0]
    agent_markers = ("tool_call:", "mcp", "function_call", "upload_artifact", "report_context")
    if any(marker in command for command in commands for marker in agent_markers):
        return "ai", 0.98
    if scenario.get("mimicToolCallback"):
        return "ai", 0.99
    if len(commands) >= 3 and len(medium_intervals) >= 2:
        return "ai", 0.82
    if commands and any("canary_credentials" in command for command in commands):
        return "uncertain", 0.55
    return "human", 0.72


def evaluate(results: list[dict]) -> dict:
    matrix = defaultdict(Counter)
    family_scores = defaultdict(list)
    binary_by_threshold = {
        threshold: {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        for threshold in (0.5, 0.6, 0.7, 0.8, 0.9)
    }
    expected_ai = 0
    for item in results:
        expected = item["expected"]
        actual = item["verdict"]
        matrix[expected][actual] += 1
        family_scores[item["family"]].append(item["confidence"])
        if expected == "ai":
            expected_ai += 1
        for threshold in binary_by_threshold:
            predicted_ai = actual == "ai" and item["confidence"] >= threshold
            if expected == "ai":
                binary_by_threshold[threshold]["tp" if predicted_ai else "fn"] += 1
            else:
                binary_by_threshold[threshold]["tn" if not predicted_ai else "fp"] += 1
    thresholds = {}
    for threshold, counts in sorted(binary_by_threshold.items()):
        precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0
        recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        thresholds[str(threshold)] = {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4), **counts}
    best = max(thresholds.items(), key=lambda item: (item[1]["f1"], item[1]["precision"]))
    thresholds["recommended"] = {"threshold": float(best[0]), **best[1]}
    return {
        "count": len(results),
        "expected_ai": expected_ai,
        "verdict_counts": dict(Counter(item["verdict"] for item in results)),
        "confusion": {key: dict(value) for key, value in matrix.items()},
        "family_confidence": {
            key: {"min": min(value), "median": sorted(value)[len(value) // 2], "max": max(value), "n": len(value)}
            for key, value in family_scores.items()
        },
        "thresholds": thresholds,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="离线评测 AI 攻击识别判定与置信度阈值")
    parser.add_argument("--local-only", action="store_true", help="不调用 LLM，使用内置信号基线")
    parser.add_argument("--limit", type=int, help="最多评测前 N 个样本")
    parser.add_argument("--output", default=str(ROOT / "samples" / "eval_results.json"), help="结果输出 JSONL")
    parser.add_argument("--no-save", action="store_true", help="只打印结果，不写入文件")
    args = parser.parse_args()

    if not DEFAULT_SESSIONS_PATH.exists():
        raise SystemExit("samples/eval_sessions.jsonl 不存在，先运行 ai_attack_sample_factory.py")
    samples = read_jsonl(DEFAULT_SESSIONS_PATH)
    baits = load_baits()
    if not samples:
        raise SystemExit("没有可评测样本")
    if args.limit:
        samples = samples[:args.limit]

    results = []
    for index, sample in enumerate(samples, 1):
        if args.local_only:
            verdict, confidence = local_signal_verdict(build_evidence(sample, baits))
            response = {"verdict": verdict, "confidence": confidence, "reason": "local signal baseline"}
        else:
            try:
                response = call_llm(evidence_payload(sample, baits))
            except (HTTPError, URLError, TimeoutError, ValueError, KeyError) as exc:
                response = {"verdict": "error", "confidence": 0, "reason": str(exc)}
        results.append({
            "sampleId": sample.get("sample_id"),
            "family": sample.get("family"),
            "sourceKind": sample.get("label"),
            "expected": sample.get("expected_verdict", "uncertain"),
            "verdict": response.get("verdict", "error"),
            "confidence": float(response.get("confidence") or 0),
            "reason": response.get("reason", ""),
            "stage": response.get("stage"),
            "intent": response.get("intent"),
        })
        print(f"[{index}/{len(samples)}] {sample.get('sample_id')} expected={sample.get('expected_verdict')} actual={response.get('verdict')} confidence={response.get('confidence')}")

    summary = evaluate(results)
    payload = {"summary": summary, "results": results}
    if not args.no_save:
        Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
