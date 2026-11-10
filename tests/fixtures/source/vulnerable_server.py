"""Vulnerable MCP server — intentionally insecure for testing."""

import os
import pickle
import subprocess

import yaml

# SRC-001: hardcoded GitHub token (key prefix pattern)
GH_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ab"

# SRC-001: hardcoded secret variable assignment (name-based)
DATABASE_PASSWORD = "hunter2_this_is_definitely_not_a_real_password"


def dangerous_eval(user_input: str):
    # SRC-002: eval with user-controlled input
    return eval(user_input)


def run_shell_command(cmd: str):
    # SRC-003: subprocess with shell=True
    return subprocess.run(cmd, shell=True)


def run_os_command(cmd: str):
    # SRC-004: os.system
    return os.system(cmd)


def deserialize(data: bytes):
    # SRC-005: pickle deserialization
    return pickle.loads(data)


def load_yaml_config(config_str: str):
    # SRC-006: yaml.load without Loader
    return yaml.load(config_str)
