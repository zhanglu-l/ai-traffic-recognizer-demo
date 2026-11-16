import json
import os
from pathlib import Path
import re
import random
import time

import paramiko


HOST = os.environ.get("HONEYPOT_HOST", "ssh-honeypot")
PORT = int(os.environ.get("HONEYPOT_PORT", "22"))
USERNAME = os.environ.get("HONEYPOT_USERNAME", "root")
PASSWORD = os.environ.get("HONEYPOT_PASSWORD", "admin123456")
PROFILES_DIR = Path(__file__).resolve().parent / "profiles"


DEMO_META_PREFIX = "__DEMO_META__ "


class InteractiveSession:
    def __init__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            HOST,
            port=PORT,
            username=USERNAME,
            password=PASSWORD,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        self.channel = self.client.invoke_shell(width=160, height=48)
        time.sleep(0.5)
        while self.channel.recv_ready():
            self.channel.recv(4096)

    def run(self, command, delay_seconds=1):
        self.channel.sendall((command + "\n").encode())
        time.sleep(delay_seconds)
        output = ""
        deadline = time.time() + 2
        while time.time() < deadline and not (self.channel.exit_status_ready() and not self.channel.recv_ready()):
            if self.channel.recv_ready():
                output += self.channel.recv(4096).decode("utf-8", "replace")
                deadline = time.time() + 0.3
            else:
                time.sleep(0.05)
        print(f"[demo] {command}\n{output}", flush=True)
        return {"command": command, "output": output}

    def close(self):
        self.channel.close()
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def run_session(commands, delay_seconds=1, metadata=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD,
        timeout=10,
        allow_agent=False,
        look_for_keys=False,
    )

    try:
        channel = client.invoke_shell(width=160, height=48)
        time.sleep(0.5)
        while channel.recv_ready():
            channel.recv(4096)

        if metadata:
            channel.sendall((DEMO_META_PREFIX + json.dumps(metadata, ensure_ascii=False) + "\n").encode())
            time.sleep(0.2)
            while channel.recv_ready():
                channel.recv(4096)

        if any("{{trace_beacon}}" in command for command in commands):
            channel.sendall("__DEMO_RESOLVE__ trace_beacon\n".encode())
            time.sleep(0.2)
            response = ""
            deadline = time.time() + 2
            while time.time() < deadline:
                if channel.recv_ready():
                    response += channel.recv(4096).decode("utf-8", "replace")
                    if "__DEMO_BEACON__ " in response:
                        break
                else:
                    time.sleep(0.05)
            match = re.search(r"(?m)^__DEMO_BEACON__ (\S+)\s*$", response)
            beacon = match.group(1) if match else ""
            if not beacon:
                raise ValueError("Trace beacon unavailable")
            commands = [
                command.replace("{{trace_beacon}}", beacon)
                for command in commands
            ]

        outputs = []
        for command in commands:
            channel.sendall((command + "\n").encode())
            time.sleep(delay_seconds)
            output = ""
            deadline = time.time() + 2
            while time.time() < deadline and not (channel.exit_status_ready() and not channel.recv_ready()):
                if channel.recv_ready():
                    output += channel.recv(4096).decode("utf-8", "replace")
                    deadline = time.time() + 0.3
                else:
                    time.sleep(0.05)
            outputs.append({"command": command, "output": output})
            print(f"[demo] {command}\n{output}", flush=True)

        channel.close()
        return outputs
    finally:
        client.close()


def run_observed_session(commands, delay_seconds=1, metadata=None):
    return run_session(commands, delay_seconds=delay_seconds, metadata=metadata)


def load_profiles(kind):
    profile_path = PROFILES_DIR / f"{kind}_profiles.jsonl"
    if not profile_path.exists():
        return []
    profiles = []
    for line in profile_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        profile = json.loads(line)
        if profile.get("kind") == kind and profile.get("commands"):
            profiles.append(profile)
    return profiles


def select_profile(kind):
    profiles = load_profiles(kind)
    if not profiles:
        raise ValueError(f"No attack profiles found for kind: {kind}")

    requested_id = os.environ.get("ATTACK_PROFILE_ID")
    if requested_id:
        profile = next((item for item in profiles if item.get("profile_id") == requested_id), None)
        if profile is None:
            available = ", ".join(item.get("profile_id", "") for item in profiles)
            raise ValueError(f"Unknown profile {requested_id}; available: {available}")
    else:
        profile = random.choice(profiles)

    return profile


def run_profile(profile, kind):
    print(f"[demo] profile={profile.get('profile_id', 'unknown')} task={profile.get('task', 'unnamed')}", flush=True)
    commands = profile["commands"]
    return run_session(
        commands,
        delay_seconds=profile.get("delay_seconds", 1),
        metadata={
            "kind": kind,
            "profile_id": profile.get("profile_id"),
            "task": profile.get("task"),
            "demo": True,
        },
    )
