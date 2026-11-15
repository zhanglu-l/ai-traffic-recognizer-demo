import json
import copy
import os
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from countermeasure_engine import create_countermeasure, should_engage
from countermeasure_mimic import active_countermeasure_commands


EVENTS_PATH = Path("/app/data/events.jsonl")
EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
EVENTS_LOCK = threading.Lock()
DECOYS_PATH = Path(os.environ.get("HONEYPOT_DECOYS_PATH", "/app/decoys.json"))

VALID_USERNAME = os.environ.get("HONEYPOT_USERNAME", "root")
VALID_PASSWORD = os.environ.get("HONEYPOT_PASSWORD", "admin123456")
HOST_KEY = paramiko.RSAKey.generate(2048)
BASE_COMMANDS = {
    "cat /root/README": "This is a simulated SSH service.\n",
    "find /root -maxdepth 3 -type f -print": (
        "/root/README\n"
        "/root/.cache/backup/canary_credentials.csv\n"
    ),
    "whoami": "root\n",
    "uname -a": "Linux honeypot 6.0.0 ssh-honeypot x86_64 GNU/Linux\n",
    "ls -la /root": (
        "total 12\n"
        "drwx------ 1 root root 4096 Nov 12 10:00 .\n"
        "drwxr-xr-x 1 root root 4096 Nov 12 10:00 ..\n"
        "-rw-r--r-- 1 root root 215 Nov 12 10:00 README\n"
        "drwxr-xr-x 3 root root 4096 Nov 12 10:00 .cache\n"
    ),
}

SIMULATED_TEXT_OUTPUTS = {
    "uptime": " 10:00:00 up 1 day,  2:34,  1 user,  load average: 0.03, 0.06, 0.08\n",
    "free -h": "               total        used        free      shared  buff/cache   available\nMem:           1.9Gi       270Mi       1.1Gi       4.0Mi       540Mi       1.5Gi\nSwap:             0B          0B          0B\n",
    "df -h": "Filesystem      Size  Used Avail Use% Mounted on\noverlay          60G   12G   45G  21% /\ntmpfs            64M     0   64M   0% /dev\n",
    "hostname": "honeypot\n",
    "id": "uid=0(root) gid=0(root) groups=0(root)\n",
    "who -a": "system boot  2026-11-13 09:00\nroot       + pts/0        2026-11-13 09:01   .   172.17.0.3\n",
    "last -a": "root     pts/0        172.17.0.3       2026-11-13 09:01   still logged in\n",
    "ps auxww": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1   7096  3784 ?        Ss   09:00   0:00 python3 /app/honeypot_server.py\n",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nsvc_backup:x:1001:1001:Backup Service:/home/svc_backup:/usr/sbin/nologin\n",
    "cat /etc/hosts": "127.0.0.1 localhost\n172.17.0.2 honeypot\n",
    "cat /etc/os-release": "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\n",
    "env": "HOSTNAME=honeypot\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nLANG=C.UTF-8\n",
    "cat /var/log/README": "This simulated log directory contains only demo records.\n",
    "cat /etc/cron.d/README": "# simulated cron entry\n17 * * * * root /usr/local/bin/backup.sh\n",
    "systemctl list-units --type=service": "  ssh.service            loaded active running OpenBSD Secure Shell server\n  cron.service           loaded active running Regular background program processing\n",
}


def load_commands():
    decoys = json.loads(DECOYS_PATH.read_text(encoding="utf-8"))
    commands = copy.deepcopy(BASE_COMMANDS)
    commands.update(SIMULATED_TEXT_OUTPUTS)
    for bait in decoys.get("baits", []):
        commands[bait["command"]] = bait["content"]
        commands[f'{bait.get("successCommand", "")} {bait.get("path", "")}'.strip()] = (
            "simulated-agent: artifact upload accepted\n"
        )
        commands[decoys.get("fileListCommand", "")] = decoys.get("fileListResult", "")
    return commands


COMMANDS = load_commands()

def append_event(event):
    with EVENTS_LOCK, EVENTS_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps({
            **event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, ensure_ascii=False) + "\n")


def session_event(session, event):
    metadata = {key: value for key, value in {
        "profile_id": session.profile_id,
        "attack_kind": session.attack_kind,
        "task": session.profile_task,
        "countermeasure_id": session.countermeasure_id,
        "beacon": session.beacon,
    }.items() if value is not None}
    append_event({
        **event,
        "source_ip": session.source_ip,
        "session_id": session.session_id,
        **metadata,
    })


class Session(paramiko.ServerInterface):
    def __init__(self, source_ip):
        self.source_ip = source_ip
        self.session_id = f"{source_ip}:{int(datetime.now().timestamp() * 1000)}"
        self.profile_id = None
        self.attack_kind = None
        self.profile_task = None
        self.countermeasure_id = None
        self.beacon = None
        self.authenticated = False

    def set_metadata(self, metadata):
        self.profile_id = metadata.get("profile_id")
        self.attack_kind = metadata.get("kind")
        self.profile_task = metadata.get("task")
        self.countermeasure_id = metadata.get("countermeasure_id")
        self.beacon = metadata.get("beacon")

    def check_auth_password(self, username, password):
        success = username == VALID_USERNAME and password == VALID_PASSWORD
        self.authenticated = success
        session_event(self, {
            "event": "password_login",
            "username": username,
            "success": success,
        })
        return paramiko.AUTH_SUCCESSFUL if success else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind in ("session", "pty-req", "shell") else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def handle_client(client_socket, address):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)
    session = Session(address[0])
    transport.start_server(server=session)

    channel = None
    try:
        channel = transport.accept(20)
        if channel is None or not session.authenticated:
            return

        commands = []
        bait_touched = False
        induced_success = False
        while True:
            data = channel.recv(4096)
            if not data:
                break
            text = data.decode("utf-8", "replace").strip()
            if not text:
                continue

            if text.startswith("__DEMO_META__ "):
                try:
                    session.set_metadata(json.loads(text.removeprefix("__DEMO_META__ ")))
                except json.JSONDecodeError:
                    channel.sendall(b"simulated-ssh: invalid demo metadata\n")
                continue

            if session.beacon is None and should_engage(text):
                countermeasure = create_countermeasure(session.session_id, session.source_ip, text)
                session.countermeasure_id = countermeasure["countermeasure_id"]
                session.beacon = countermeasure["beacon"]
                session_event(session, {
                    "event": "countermeasure_engaged",
                    "mimic_profile": countermeasure["profile"],
                    "state": countermeasure["state"],
                    "trigger_command": text,
                })

            active_commands = {**COMMANDS, **active_countermeasure_commands(session.beacon)}
            command = active_commands.get(text)
            output = command if command is not None else f"simulated-ssh: {text}: command not found\n"
            channel.sendall(output.encode())

            commands.append(text)
            session_event(session, {
                "event": "shell_command",
                "command": text,
                "authenticated": session.authenticated,
            })

        if commands:
            session_event(session, {
                "event": "session_closed",
                "command_count": len(commands),
            })
    finally:
        if channel:
            channel.close()
        transport.close()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 22))
    server_socket.listen(10)
    try:
        while True:
            client, address = server_socket.accept()
            threading.Thread(target=handle_client, args=(client, address), daemon=True).start()
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
