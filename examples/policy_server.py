"""Minimal Flask policy server for MCP Shield.

Serves a JSON policy over HTTPS with X-API-Key auth and ETag caching.
Replace POLICY and API_KEY with your actual values, or load them from
your policy store (Git, database, secrets manager, etc.).

Usage:
  pip install flask
  MCP_SHIELD_POLICY_KEY=secret flask --app policy_server run --host 0.0.0.0 --port 8080

In MCP Shield local.yaml:
  policy_source: https://your-host:8080/policy
  fallback_mode: fail-open
  # Set MCP_SHIELD_API_KEY=secret in the environment where mcp-shield runs
"""

import hashlib
import json
import os

from flask import Flask, abort, jsonify, request

app = Flask(__name__)

API_KEY = os.environ.get("MCP_SHIELD_POLICY_KEY", "change-me")

POLICY = {
    "default_action": "log",
    "severity_threshold": "low",
    "servers": {
        "filesystem": {
            "default_action": "redact",
            "severity_threshold": "medium",
        },
    },
    "tools": {
        "github.create_issue": {
            "default_action": "block",
            "severity_threshold": "high",
        },
    },
}

_POLICY_BYTES = json.dumps(POLICY, sort_keys=True).encode()
_ETAG = '"' + hashlib.sha256(_POLICY_BYTES).hexdigest()[:16] + '"'


@app.route("/policy")
def policy():
    if request.headers.get("X-API-Key") != API_KEY:
        abort(401)

    if request.headers.get("If-None-Match") == _ETAG:
        return "", 304, {"ETag": _ETAG}

    return jsonify(POLICY), 200, {"ETag": _ETAG}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
