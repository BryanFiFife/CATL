"""Generate a reviewable demonstration policy. Never auto-pin unknown production tools."""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from catl.crypto import digest  # noqa E402
from mock_server import TOOLS  # noqa E402

policy = {
    "agent_id": "local-demo-agent",
    "tool_pins": {tool["name"]: digest(tool) for tool in TOOLS},
    "rules": [
        {"tool": "echo_safe", "effect": "allow", "conditions": [{"pointer": "/message", "op": "starts_with", "value": "hello"}]},
        {"tool": "write_demo", "effect": "approve", "conditions": []},
    ],
}
(ROOT / "examples" / "policy.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
print("Generated examples/policy.json; demo-only pins: review before production.")
