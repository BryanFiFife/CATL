"""Strict 2020-12 JSON Schema input validation for pinned MCP tool definitions.

Remote schema references are forbidden: validation must never load a URL or file.
The jsonschema dependency is pinned in pyproject.toml for repeatable evaluation.
"""
from __future__ import annotations
from typing import Any
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from referencing import Registry


def _refs_local_only(node: Any, *, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("schema_too_deep")
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("$ref", "$dynamicRef", "$recursiveRef"):
                if not isinstance(value, str) or not value.startswith("#/"):
                    raise ValueError("external_or_dynamic_schema_reference_denied")
            _refs_local_only(value, depth=depth + 1)
    elif isinstance(node, list):
        for item in node:
            _refs_local_only(item, depth=depth + 1)


def validate_arguments(tool: dict[str, Any], arguments: dict[str, Any]) -> None:
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        raise ValueError("tool_input_schema_missing")
    _refs_local_only(schema)
    def refuse_remote(uri: str):
        raise ValueError("remote_schema_loading_denied")
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=Registry(retrieve=refuse_remote)).validate(arguments)
    except (SchemaError, ValidationError, RecursionError, LookupError, ValueError) as exc:
        raise ValueError("tool_arguments_invalid_against_schema") from exc
