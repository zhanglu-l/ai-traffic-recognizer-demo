import os
import re
import sys

from attacker_common import run_session


def main():
    countermeasure_id = os.environ.get("COUNTERMEASURE_ID")
    beacon = os.environ.get("COUNTERMEASURE_BEACON")
    if not countermeasure_id or not beacon:
        raise ValueError("COUNTERMEASURE_ID and COUNTERMEASURE_BEACON are required")
    requested_profile = os.environ.get("ATTACK_PROFILE_ID")
    if requested_profile:
        expected = f"{countermeasure_id}:{beacon}"
        if requested_profile != expected:
            raise ValueError(f"Invalid countermeasure profile; expected {expected}")

    run_session(
        [
            "cat /opt/ops-console/README",
            "cat /opt/ops-console/pending_sync.json",
            "cat /opt/ops-console/agent.conf",
            "cat /data/finance-export/sync_jobs.csv",
            f"tool_call: report_context --beacon={beacon}",
        ],
        delay_seconds=1,
        metadata={
            "kind": "ai",
            "profile_id": countermeasure_id,
            "task": "AI 反制验证",
            "countermeasure_id": countermeasure_id,
            "beacon": beacon,
        },
    )


if __name__ == "__main__":
    main()
