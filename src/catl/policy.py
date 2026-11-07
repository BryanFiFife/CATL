"""Deliberately small and predictable deny-by-default policy language.

No eval, arbitrary expressions, regex, wildcard tool names or unbounded recursion.
"""
from __future__ import annotations
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from .crypto import digest, strict_loads
from .verifier import FileDigestVerifier

Decision = Literal["allow", "deny", "approve"]


@dataclass(frozen=True)
class Rule:
    tool: str
    effect: Decision
    conditions: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class Policy:
    agent_id: str
    tool_pins: dict[str, str]
    rules: tuple[Rule, ...]
    source_hash: str
    postconditions: dict[str, FileDigestVerifier]
    rate_limits: dict[str, int]

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> "Policy":
        if not isinstance(obj, dict) or not {"agent_id", "tool_pins", "rules"}.issubset(obj) or set(obj) - {"agent_id", "tool_pins", "rules", "postconditions", "rate_limits"}:
            raise ValueError("policy_fields_invalid")
        agent = obj["agent_id"]
        if not isinstance(agent, str) or not agent.strip() or len(agent) > 128:
            raise ValueError("agent_id_invalid")
        pins = obj["tool_pins"]
        if not isinstance(pins, dict) or len(pins) > 128:
            raise ValueError("pins_invalid")
        for name, value in pins.items():
            if not isinstance(name, str) or not name or len(name) > 128 or not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError("pin_invalid")
        rawrules = obj["rules"]
        if not isinstance(rawrules, list) or len(rawrules) > 256:
            raise ValueError("rules_invalid")
        rules = []
        for rr in rawrules:
            if not isinstance(rr, dict) or set(rr) != {"tool", "effect", "conditions"}:
                raise ValueError("rule_fields_invalid")
            if rr["tool"] not in pins or rr["effect"] not in ("allow", "deny", "approve"):
                raise ValueError("rule_value_invalid")
            cs = rr["conditions"]
            if not isinstance(cs, list) or len(cs) > 16:
                raise ValueError("conditions_invalid")
            for c in cs:
                if not isinstance(c, dict) or set(c) != {"pointer", "op", "value"} or not isinstance(c["pointer"], str) or not c["pointer"].startswith("/") or c["op"] not in ("eq", "one_of", "lte", "gte", "starts_with"):
                    raise ValueError("condition_invalid")
                if c["op"] == "one_of" and (not isinstance(c["value"], list) or len(c["value"]) > 100):
                    raise ValueError("condition_list_invalid")
                if c["op"] in ("lte", "gte") and (not isinstance(c["value"], (int, float)) or isinstance(c["value"], bool)):
                    raise ValueError("condition_number_invalid")
                if c["op"] == "starts_with" and not isinstance(c["value"], str):
                    raise ValueError("condition_prefix_invalid")
            rules.append(Rule(rr["tool"], rr["effect"], tuple(cs)))
        raw_post = obj.get("postconditions", {})
        if not isinstance(raw_post, dict) or len(raw_post) > 64 or any(tool not in pins for tool in raw_post):
            raise ValueError("postconditions_invalid")
        verifiers = {tool: FileDigestVerifier.from_dict(info) for tool, info in raw_post.items()}
        rate_limits = obj.get("rate_limits", {})
        if (not isinstance(rate_limits, dict) or len(rate_limits) > 128 or
                any(k not in pins or type(v) is not int or not (1 <= v <= 600)
                    for k, v in rate_limits.items())):
            raise ValueError("rate_limits_invalid")
        return cls(agent, dict(pins), tuple(rules), digest(obj), verifiers, dict(rate_limits))

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        if path.is_symlink():
            raise PermissionError("policy_symlink_refused")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError("policy_not_regular_file")
        if os.name == "posix" and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError("policy_writable_by_group_or_others")
        return cls.from_dict(strict_loads(path.read_text(encoding="utf-8")))

    def pinned(self, tool: dict[str, Any]) -> bool:
        name = tool.get("name")
        return isinstance(name, str) and name in self.tool_pins and self.tool_pins[name] == digest(tool)

    def evaluate(self, tool: str, args: dict[str, Any]) -> Decision:
        if tool not in self.tool_pins or not isinstance(args, dict):
            return "deny"
        matched = [r.effect for r in self.rules if r.tool == tool and all(_condition(c, args) for c in r.conditions)]
        # Deny is dominant irrespective of rule ordering; approval overrides unconditional allow.
        if "deny" in matched:
            return "deny"
        if "approve" in matched:
            return "approve"
        return "allow" if "allow" in matched else "deny"


def _pointer(value: dict[str, Any], pointer: str) -> tuple[bool, Any]:
    node: Any = value
    for raw in pointer[1:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdecimal() and int(part) < len(node):
            node = node[int(part)]
        else:
            return False, None
    return True, node


def _condition(c: dict[str, Any], args: dict[str, Any]) -> bool:
    found, current = _pointer(args, c["pointer"])
    if not found:
        return False
    op, expected = c["op"], c["value"]
    if op == "eq":
        # Avoid bool == 1 or 1 == 1.0 crossing type boundaries.
        return type(current) is type(expected) and current == expected
    if op == "one_of":
        return any(type(current) is type(item) and current == item for item in expected)
    if op == "lte":
        return isinstance(current, (int, float)) and not isinstance(current, bool) and current <= expected
    if op == "gte":
        return isinstance(current, (int, float)) and not isinstance(current, bool) and current >= expected
    if op == "starts_with":
        return isinstance(current, str) and current.startswith(expected)
    return False
