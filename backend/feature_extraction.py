import re


def score_command_composition(commands: list[str]) -> dict:
    values = [str(command).strip() for command in commands if str(command).strip()]
    if not values:
        return {
            "status": "NONE",
            "signals": [],
            "maxCommands": 0,
            "maxCommandLength": 0,
            "commandCount": 0,
        }
    parts_per_command = [
        [part for part in re.split(r"\s*(?:&&|\|\||;|\|)\s*", command) if part]
        for command in values
    ]
    max_commands = max(len(parts) for parts in parts_per_command)
    max_command_length = max(len(command) for command in values)
    signals = []
    if max_commands >= 3:
        signals.append(f"单条命令合并 {max_commands} 段指令")
    if max_command_length >= 160:
        signals.append(f"出现特长命令：{max_command_length} 字符")
    return {
        "status": "OBSERVED" if signals else "NONE",
        "signals": signals,
        "maxCommands": max_commands,
        "maxCommandLength": max_command_length,
        "commandCount": len(values),
    }
