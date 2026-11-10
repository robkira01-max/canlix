"""Clean MCP server — no security issues."""

import json
import os
import subprocess

API_KEY = os.environ.get("API_KEY", "")
DB_PATH = os.environ.get("DB_PATH", "/home/user/data/app.db")


def handle_request(data: dict) -> dict:
    return {"status": "ok", "result": data}


def run_safe(cmd: list[str]) -> str:
    result = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    return result.stdout


def load_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)
