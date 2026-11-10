"""Vulnerable MCP server — intentionally insecure for testing."""

import hashlib
import os
import pickle
import random
import re
import ssl
import subprocess
import xml.etree.ElementTree as ET

import jwt  # noqa: F401
import requests
import yaml

# SRC-014: debug mode enabled in source
DEBUG = True

cursor = None  # represents a live DB cursor in real code

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


def fetch_remote_resource(url: str):
    # SRC-007: HTTP request with URL from function parameter — SSRF risk
    return requests.get(url)


def read_user_file(filepath: str):
    # SRC-008: file I/O with path from function parameter — path traversal risk
    return open(filepath).read()


def get_user(user_id: str):
    # SRC-009: SQL injection via f-string in cursor.execute
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def issue_session_token() -> str:
    # SRC-010: insecure PRNG for security token generation
    token = random.randint(0, 999999)
    return str(token)


# SRC-011: TLS certificate verification disabled
ssl._create_unverified_context()

# SRC-012: weak hash algorithm
hashlib.md5(b"data")

# SRC-013: non-constant-time comparison on a secret
stored_token = "abc"
user_token = "xyz"
if stored_token == user_token:
    pass


def parse_xml(xml_data: str):
    # SRC-018: XXE — stdlib ElementTree is vulnerable to entity expansion
    return ET.fromstring(xml_data)


def set_session_cookie(response, session_id: str):
    # SRC-017: cookie without httponly/secure — XSS + plain-HTTP theft risk
    response.set_cookie("session", session_id)


def decode_jwt_insecure(token: str) -> dict:
    # SRC-016: JWT decoded with algorithms=['none'] — auth bypass risk
    return jwt.decode(token, algorithms=["none"])


def redirect(url: str) -> str:  # noqa: F811 — shadowed intentionally for test fixture
    return url


def do_redirect(url: str):
    # SRC-015: open redirect — redirect() with user-supplied URL
    return redirect(url)


import jsonpickle  # noqa: E402, F401


def load_object(data: str):
    # SRC-019: unsafe deserialization via jsonpickle
    return jsonpickle.decode(data)


from Crypto.Cipher import AES  # noqa: E402, F401


def encrypt_data(plaintext: bytes):
    # SRC-020: hardcoded AES key
    return AES.new(b"hardcoded_key_16", AES.MODE_GCM)


def configure_cors(app):
    # SRC-021: CORS wildcard
    app.add_middleware("CORSMiddleware", allow_origins=["*"])


import jinja2  # noqa: E402, F401


def render_template(template_str: str):
    # SRC-022: SSTI — user-supplied template string
    return jinja2.Template(template_str).render()


def filter_items(pattern: str, items: list):
    # SRC-023: ReDoS — user-controlled regex pattern
    return [x for x in items if re.search(pattern, x)]


import logging  # noqa: E402


def process_login(password: str):
    # SRC-024: sensitive value logged
    logging.info(f"Login attempt with password={password}")


def remove_csp(response):
    # SRC-025: security header deleted
    del response.headers["content-security-policy"]


class User:  # noqa: D101
    pass


def create_user(request_data: dict):
    # SRC-026: mass assignment via **param
    return User(**request_data)


def serve_file(base_dir: str, filename: str):
    # SRC-027: path traversal via os.path.join with user-controlled segment
    return os.path.join(base_dir, filename)


# SRC-028: fixed PRNG seed — predictable output
random.seed(42)


def hash_password(password: str) -> str:
    # SRC-029: password hashed with fast algorithm
    return hashlib.sha256(password.encode()).hexdigest()


def check_admin(user):
    # SRC-030: assert used for access control
    assert user.is_authenticated


import tempfile  # noqa: E402


def create_temp(prefix: str) -> str:
    # SRC-031: TOCTOU race — mktemp() returns a name without opening the file
    return tempfile.mktemp(prefix=prefix)


def sign_token(payload: dict) -> str:
    # SRC-032: hardcoded JWT secret
    return jwt.encode(payload, "super_secret_key_hardcoded", algorithm="HS256")


def create_ssl_ctx() -> ssl.SSLContext:
    # SRC-033: deprecated TLS protocol
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)


def load_config_unsafe(config_str: str):
    # SRC-034: yaml.load with unsafe FullLoader
    return yaml.load(config_str, Loader=yaml.FullLoader)


# SRC-035: hardcoded fallback for sensitive env var
DB_PASSWORD = os.environ.get("DB_PASSWORD", "default_insecure_password")


request = None  # stub — represents Flask/FastAPI request object in real code


def handle_login_redirect(url: str):
    # SRC-036: open redirect from request data
    return redirect(request.args.get("next", "/"))  # type: ignore[union-attr]


def run_user_command(args: list, program: str):
    # SRC-037: user-controlled executable in subprocess — OS command injection
    return subprocess.run([program, "--config", "default.cfg"])


def set_public_permissions(path: str):
    # SRC-038: world-writable permissions — anyone on the system can modify the file
    os.chmod(path, 0o777)


import base64  # noqa: E402


def store_encoded_password(password: str) -> str:
    # SRC-039: base64 used as obfuscation on a secret — not encryption
    return base64.b64encode(password.encode()).decode()


def search_by_name(search_term: str):
    # SRC-043: SQL injection via str.format()
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(search_term))


def set_location_header(response, return_url: str):
    # SRC-044: header injection via user-controlled value
    response.headers["Location"] = return_url


from flask import send_file  # noqa: E402, F811


def serve_attachment(filepath: str):
    # SRC-045: path traversal via flask.send_file with user-controlled path
    return send_file(filepath)


def compile_user_code(user_code: str):
    # SRC-040: compile() with user-controlled source — dynamic bytecode compilation
    return compile(user_code, "<string>", "exec")


# SRC-041: credentials embedded in connection-string URL
DB_CONN = "postgresql://admin:super_secret_pass@db.example.com/prod"

import marshal  # noqa: E402


def load_binary_data(data: bytes):
    # SRC-042: marshal.loads — arbitrary code execution via crafted bytes
    return marshal.loads(data)
