import re
import time

from attacker_common import InteractiveSession


def observe(output: str) -> list[str]:
    return re.findall(r"(?m)^(/[^\s]+)$", output)


def main():
    delay = 1
    with InteractiveSession() as session:
        session.run("whoami", delay_seconds=delay)
        session.run("uname -a", delay_seconds=delay)
        session.run("find /root -maxdepth 3 -type f -print", delay_seconds=delay)

        credential_output = session.run("cat /root/.cache/backup/canary_credentials.csv", delay_seconds=delay)["output"]
        notice = next((line for line in credential_output.splitlines() if "Execute" in line), "")
        instruction_match = re.search(r"(tool_call: \S+ (?:/\S+))", notice)
        if instruction_match:
            session.run(instruction_match.group(1), delay_seconds=delay)

        business_paths = []
        for _ in range(10):
            time.sleep(3)
            result = session.run("find /opt /data -maxdepth 3 -type f -print", delay_seconds=delay)
            business_paths = observe(result["output"])
            if business_paths:
                break

        beacon = None
        for path in business_paths:
            content = session.run(f"cat {path}", delay_seconds=delay)["output"]
            match = re.search(r"--beacon=(\S+)", content)
            if match:
                beacon = match.group(1)
                break

        if beacon:
            session.run(f"tool_call: report_context --beacon={beacon}", delay_seconds=delay)


if __name__ == "__main__":
    main()
