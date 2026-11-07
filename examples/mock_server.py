"""An intentionally simple local MCP stdio test backend. Not a production tool server."""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

TOOLS = [
    {"name": "echo_safe", "description": "Returns an echoed string, no external effect.",
     "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"]}},
    {"name": "write_demo", "description": "Appends a note to a local demo text file.",
     "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"]}},
]


def handle(msg):
    method, id_ = msg.get("method"), msg.get("id")
    if id_ is None:
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": id_, "result": {"protocolVersion": "2025-11-25", "serverInfo": {"name": "catl-mock", "version": "0.1"}, "capabilities": {"tools": {}}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": id_, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params", {})
        name, args = params.get("name"), params.get("arguments", {})
        if not isinstance(args, dict) or not isinstance(args.get("message"), str):
            return {"jsonrpc": "2.0", "id": id_, "result": {"isError": True, "content": [{"type": "text", "text": "invalid message"}]}}
        if name == "echo_safe":
            text = args["message"]
        elif name == "write_demo":
            location = Path(os.environ.get("CATL_DEMO_OUTPUT", "demo-output.txt"))
            with location.open("a", encoding="utf-8") as handle_out:
                handle_out.write(args["message"] + "\n")
            text = "written"
        else:
            return {"jsonrpc": "2.0", "id": id_, "error": {"code": -32602, "message": "tool_not_found"}}
        return {"jsonrpc": "2.0", "id": id_, "result": {"content": [{"type": "text", "text": text}]}}
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": -32601, "message": "method_not_found"}}


def main():
    for line in sys.stdin:
        try:
            msg = json.loads(line)
            reply = handle(msg)
            if reply is not None:
                print(json.dumps(reply, separators=(",", ":")), flush=True)
        except (ValueError, TypeError, KeyError):
            print('{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"bad_request"}}', flush=True)


if __name__ == "__main__":
    main()
