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


def validate_structured_output(tool: dict[str, Any], result: dict[str, Any]) -> None:
    """Validate a tool's optional structured output under its PINNED local schema.

    A declared outputSchema is not an optional advisory when a tool reports
    success. A mismatch leaves the execution outcome uncertain, because the
    backend may already have produced side effects. No remote schema retrieval.
    """
    schema = tool.get("outputSchema")
    if schema is None:
        return
    if not isinstance(schema, dict):
        raise ValueError("tool_output_schema_invalid")
    _refs_local_only(schema)
    if result.get("isError") is True:
        return  # Error payloads have no obligation to match success schemas.
    structured = result.get("structuredContent")
    if not isinstance(structured, dict):
        raise ValueError("tool_structured_content_missing")
    def refuse_remote(uri: str):
        raise ValueError("remote_schema_loading_denied")
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=Registry(retrieve=refuse_remote)).validate(structured)
    except (SchemaError, ValidationError, RecursionError, LookupError, ValueError) as exc:
        raise ValueError("tool_structured_content_invalid") from exc
