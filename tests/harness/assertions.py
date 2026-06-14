"""IRC line parser and assertion helpers."""

import re


def parse_irc_line(line):
    """Parse an IRC line into (tags, prefix, command, params).

    Returns a dict with keys: tags, prefix, command, params.
    """
    result = {"tags": {}, "prefix": None, "command": None, "params": []}

    # Parse tags (@key=val;key2)
    if line.startswith("@"):
        tag_str, line = line.split(" ", 1)
        tag_str = tag_str[1:]  # strip @
        for tag in tag_str.split(";"):
            if "=" in tag:
                k, v = tag.split("=", 1)
                result["tags"][k] = v
            else:
                result["tags"][tag] = None

    # Parse prefix (:server.name or :nick!user@host)
    if line.startswith(":"):
        prefix, line = line.split(" ", 1)
        result["prefix"] = prefix[1:]  # strip :

    # Parse command and params
    parts = line.split(" ")
    result["command"] = parts[0]

    # Parse params (trailing :param with spaces)
    params = []
    i = 1
    while i < len(parts):
        if parts[i].startswith(":"):
            params.append(" ".join(parts[i:])[1:])
            break
        params.append(parts[i])
        i += 1
    result["params"] = params

    return result


def assert_numeric(line, numeric, target=None):
    """Assert that a line is a specific IRC numeric.

    Args:
        line: Raw IRC line string
        numeric: Expected numeric (e.g., "001", "432")
        target: Expected target nick (optional)
    """
    parsed = parse_irc_line(line)
    assert parsed["command"] == numeric, (
        f"Expected numeric {numeric}, got {parsed['command']} in: {line}"
    )
    if target is not None:
        assert len(parsed["params"]) > 0 and parsed["params"][0] == target, (
            f"Expected target {target}, got {parsed['params']} in: {line}"
        )


def assert_has_tag(line, tag_name, expected_value=None):
    """Assert that a line has a specific IRCv3 message tag."""
    parsed = parse_irc_line(line)
    assert tag_name in parsed["tags"], (
        f"Expected tag {tag_name} not found in: {line}"
    )
    if expected_value is not None:
        assert parsed["tags"][tag_name] == expected_value, (
            f"Expected tag {tag_name}={expected_value}, "
            f"got {parsed['tags'][tag_name]} in: {line}"
        )


def assert_command(line, command):
    """Assert that a line has a specific IRC command."""
    parsed = parse_irc_line(line)
    assert parsed["command"] == command, (
        f"Expected command {command}, got {parsed['command']} in: {line}"
    )


def assert_prefix_nick(line, nick):
    """Assert the prefix of a line starts with the given nick."""
    parsed = parse_irc_line(line)
    assert parsed["prefix"] is not None, f"No prefix in: {line}"
    assert parsed["prefix"].split("!")[0] == nick, (
        f"Expected prefix nick {nick}, got {parsed['prefix']} in: {line}"
    )


def find_line(lines, pattern):
    """Find a line matching a pattern in a list of lines."""
    for line in lines:
        if isinstance(pattern, re.Pattern):
            if pattern.search(line):
                return line
        elif re.match(r"^\d{3}$", pattern):
            if f" {pattern} " in line:
                return line
        elif pattern in line:
            return line
    return None


def find_all_lines(lines, pattern):
    """Find all lines matching a pattern."""
    result = []
    for line in lines:
        if isinstance(pattern, re.Pattern):
            if pattern.search(line):
                result.append(line)
        elif re.match(r"^\d{3}$", pattern):
            if f" {pattern} " in line:
                result.append(line)
        elif pattern in line:
            result.append(line)
    return result
