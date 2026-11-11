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


import hashlib  # noqa: E402
import importlib  # noqa: E402
import zipfile  # noqa: E402


def hash_with_user_algo(algo: str, value: str) -> str:
    # SRC-046: dynamic hash algorithm — attacker controls the algorithm
    return hashlib.new(algo, value.encode()).hexdigest()


def load_plugin(module_name: str):
    # SRC-047: dynamic import with user-controlled name — module injection
    return importlib.import_module(module_name)


def extract_archive(archive_path: str, dest: str):
    # SRC-048: extractall() without filter — zip slip path traversal
    with zipfile.ZipFile(archive_path) as zf:
        zf.extractall(dest)


import ctypes  # noqa: E402
import socket  # noqa: E402
import threading  # noqa: E402


def disable_socket_timeout():
    # SRC-049: infinite socket timeout — stalled peer causes indefinite hang
    socket.setdefaulttimeout(None)


def load_native_library(lib_path: str):
    # SRC-050: user-controlled native library path — arbitrary code execution
    return ctypes.CDLL(lib_path)


def run_in_thread(callback: callable):
    # SRC-051: user-controlled callable in Thread target — arbitrary code execution
    t = threading.Thread(target=callback)
    t.start()


import xmlrpc.client  # noqa: E402


def get_model_attr(obj: object, method: str):
    # SRC-052: getattr with user-controlled name — arbitrary attribute access
    return getattr(obj, method)


def apply_env(env_updates: dict):
    # SRC-053: os.environ.update with user-controlled dict — environment injection
    os.environ.update(env_updates)


def call_xml_rpc(url: str):
    # SRC-054: xmlrpc SSRF via user-controlled URL
    return xmlrpc.client.ServerProxy(url)


import multiprocessing  # noqa: E402
import webbrowser  # noqa: E402

from flask import render_template_string  # type: ignore[import-untyped]  # noqa: E402


def render_user_template(template: str) -> str:
    # SRC-055: Flask SSTI — user-supplied template string executed by Jinja2
    return render_template_string(template)


def run_in_process(callback: callable) -> None:
    # SRC-056: user-controlled callable launched as a separate process
    p = multiprocessing.Process(target=callback)
    p.start()


def open_url_in_browser(url: str) -> None:
    # SRC-057: user-controlled URL opened in OS browser — open redirect / phishing
    webbrowser.open(url)


import ftplib  # noqa: E402
import smtplib  # noqa: E402

import ldap3  # noqa: E402


def connect_ftp(host: str) -> ftplib.FTP:
    # SRC-058: user-controlled FTP host — SSRF, plaintext credentials
    return ftplib.FTP(host)


def send_mail(host: str) -> smtplib.SMTP:
    # SRC-059: user-controlled SMTP host — SSRF, open relay
    return smtplib.SMTP(host)


def connect_ldap(host: str) -> ldap3.Connection:
    # SRC-060: user-controlled LDAP server — directory SSRF
    server = ldap3.Server(host)
    return ldap3.Connection(server)


import urllib.request  # noqa: E402
import zipimport  # noqa: E402


def run_shell_popen(cmd: str) -> str:
    # SRC-061: os.popen with user-controlled command — shell injection
    return os.popen(cmd).read()


def fetch_url(url: str) -> bytes:
    # SRC-062: urllib.request.urlretrieve with user-controlled URL — SSRF
    local, _ = urllib.request.urlretrieve(url)
    return open(local, "rb").read()


def load_zip_plugin(path: str) -> None:
    # SRC-063: zipimporter with user-controlled path — arbitrary zip code import
    zipimport.zipimporter(path)


import asyncio  # noqa: E402

import aiohttp  # noqa: E402


def set_obj_attr(obj: object, attr: str, value: object) -> None:
    # SRC-064: setattr with user-controlled attribute name — attribute injection
    setattr(obj, attr, value)


async def make_request_no_tls() -> None:
    # SRC-065: ssl=False disables TLS in aiohttp — MITM risk
    async with aiohttp.ClientSession() as session:
        await session.get("https://example.com", ssl=False)


async def run_async_shell(cmd: str) -> None:
    # SRC-066: asyncio.create_subprocess_shell with user-controlled command
    await asyncio.create_subprocess_shell(cmd)


import hashlib  # noqa: E402


def tcp_connect(host: str) -> None:
    # SRC-067: socket.create_connection with user-controlled host — SSRF
    socket.create_connection((host, 443))


def kdf_stretch(password: str, salt: bytes, iterations: int) -> bytes:
    # SRC-068: user-controlled iteration count — DoS via CPU exhaustion
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


def run_user_exe(exe: str) -> None:
    # SRC-069: subprocess executable= kwarg override — binary hijack
    subprocess.run(["dummy"], executable=exe)


from flask import send_from_directory  # noqa: E402


def shell_output(cmd: str) -> str:
    # SRC-070: subprocess.getoutput with user-controlled command — shell injection
    return subprocess.getoutput(cmd)


def configure_logging(log_file: str) -> None:
    # SRC-071: user-controlled log file path — write path traversal
    logging.basicConfig(filename=log_file)


def serve_dir(directory: str, filename: str):
    # SRC-072: user-controlled base directory in send_from_directory
    return send_from_directory(directory, filename)


import shlex  # noqa: E402


def run_code(user_code: str) -> None:
    # SRC-073: exec() with user-controlled code — arbitrary code execution
    exec(user_code)  # noqa: S102


def write_file(path: str, content: bytes) -> None:
    # SRC-074: open() in write mode with user-controlled path — file overwrite
    with open(path, "wb") as f:  # noqa: PTH123
        f.write(content)


def tokenise_and_run(cmd: str) -> None:
    # SRC-075: shlex.split with user-controlled input — shell tokenisation injection
    args = shlex.split(cmd)
    subprocess.run(args)


def inspect_namespace(key: str) -> object:
    # SRC-076: globals() called inside a function with parameters — namespace exposure
    return globals()[key]


def create_user_dir(path: str) -> None:
    # SRC-077: os.makedirs with user-controlled path — arbitrary directory creation
    os.makedirs(path, exist_ok=True)


def capture_output(cmd: str) -> bytes:
    # SRC-078: subprocess.check_output(cmd, shell=True) with user-controlled cmd
    return subprocess.check_output(cmd, shell=True)


import configparser  # noqa: E402


def load_user_config(config_path: str) -> configparser.ConfigParser:
    # SRC-079: user-controlled config file path — attacker chooses config source
    return configparser.ConfigParser().read(config_path)


def exec_program(exe: str, argv: list) -> None:
    # SRC-080: os.execv with user-controlled executable path — process replacement
    os.execv(exe, argv)


def move_file(src: str, dst: str) -> None:
    # SRC-081: os.rename with user-controlled source path — arbitrary file replacement
    os.rename(src, dst)


def create_named_temp(tmp_dir: str) -> None:
    # SRC-082: NamedTemporaryFile with user-controlled dir — temp directory path traversal
    tempfile.NamedTemporaryFile(dir=tmp_dir)


def make_symlink(target: str, link_path: str) -> None:
    # SRC-083: os.symlink with user-controlled target — symlink attack
    os.symlink(target, link_path)


def hard_link(src: str, dst: str) -> None:
    # SRC-084: os.link with user-controlled source path — hard link attack
    os.link(src, dst)


import signal  # noqa: E402


def open_log_file(log_path: str) -> None:
    # SRC-088: logging.FileHandler with user-controlled path — write path traversal
    logging.FileHandler(log_path)


def kill_process(pid: int) -> None:
    # SRC-089: os.kill with user-controlled PID — arbitrary process termination (DoS)
    os.kill(pid, signal.SIGTERM)


def open_archive(archive_path: str) -> None:
    # SRC-090: tarfile.open with user-controlled archive path — attacker chooses archive
    import tarfile  # noqa: PLC0415

    tarfile.open(archive_path)


import imaplib  # noqa: E402
import poplib  # noqa: E402
import sqlite3  # noqa: E402


def bind_server(sock: object, host: str) -> None:
    # SRC-094: sock.bind with user-controlled host — service may listen on wrong interface
    sock.bind((host, 8080))  # type: ignore[attr-defined]


def connect_imap(host: str) -> imaplib.IMAP4:
    # SRC-095: imaplib.IMAP4 with user-controlled host — SSRF via IMAP
    return imaplib.IMAP4(host)


def connect_pop3(host: str) -> poplib.POP3:
    # SRC-096: poplib.POP3 with user-controlled host — SSRF via POP3
    return poplib.POP3(host)


def open_user_db(db_path: str) -> sqlite3.Connection:
    # SRC-091: sqlite3.connect with user-controlled path — arbitrary DB file access
    return sqlite3.connect(db_path)


def apply_chmod(target_path: str) -> None:
    # SRC-092: os.chmod with user-controlled path — attacker picks which file to chmod
    os.chmod(target_path, 0o644)


def transfer_ownership(target_path: str) -> None:
    # SRC-093: os.chown with user-controlled path — attacker picks which file to chown
    os.chown(target_path, 0, 0)


import ast as stdlib_ast  # noqa: E402  (alias avoids conflict with the `ast` stdlib re-import above)


def tcp_connect_host(sock: object, host: str) -> None:
    # SRC-085: socket.connect with user-controlled host in tuple
    sock.connect((host, 443))  # type: ignore[attr-defined]


def safe_parse(data: str) -> object:
    # SRC-086: literal_eval with user-controlled input — DoS via nested structures
    return stdlib_ast.literal_eval(data)


def run_pipeline(cmd: str) -> None:
    # SRC-087: Popen with f-string — arg injection without shell=True
    subprocess.Popen(f"/usr/local/bin/tool --input {cmd}")


import http.client  # noqa: E402
import nntplib  # noqa: E402
import telnetlib  # noqa: E402


def fetch_nntp(host: str) -> nntplib.NNTP:
    # SRC-097: nntplib.NNTP with user-controlled host — SSRF via NNTP
    return nntplib.NNTP(host)


def open_telnet(host: str) -> telnetlib.Telnet:
    # SRC-098: telnetlib.Telnet with user-controlled host — cleartext protocol + SSRF
    return telnetlib.Telnet(host)


def make_http_conn(host: str) -> http.client.HTTPConnection:
    # SRC-099: http.client.HTTPConnection with user-controlled host — SSRF via stdlib HTTP
    return http.client.HTTPConnection(host)


import etcd3  # noqa: E402
import grpc  # noqa: E402
import paramiko  # noqa: E402
import pika  # noqa: E402
import pymongo  # noqa: E402
from kazoo.client import KazooClient  # noqa: E402


def open_ssh_transport(host: str) -> paramiko.Transport:
    # SRC-100: paramiko.Transport with user-controlled host — SSRF via SSH transport
    return paramiko.Transport(host)


def open_grpc_channel(target: str):
    # SRC-101: grpc.insecure_channel with user-controlled target — SSRF via gRPC
    return grpc.insecure_channel(target)


def open_mongo_client(host: str) -> pymongo.MongoClient:
    # SRC-102: pymongo.MongoClient with user-controlled host — SSRF via MongoDB client
    return pymongo.MongoClient(host)


def amqp_connect(host: str) -> pika.ConnectionParameters:
    # SRC-103: pika.ConnectionParameters with user-controlled host — SSRF via AMQP
    return pika.ConnectionParameters(host)


def zk_connect(hosts: str) -> KazooClient:
    # SRC-104: KazooClient with user-controlled hosts — SSRF via ZooKeeper
    return KazooClient(hosts)


def etcd_connect(host: str):
    # SRC-105: etcd3.client with user-controlled host — SSRF via etcd
    return etcd3.client(host)


import cassandra.cluster  # noqa: E402
import couchdb  # noqa: E402
import elasticsearch  # noqa: E402


def cassandra_connect(contact_points: str):
    # SRC-106: Cluster with user-controlled contact points — SSRF via Cassandra
    return cassandra.cluster.Cluster(contact_points)


def es_connect(hosts: str):
    # SRC-107: Elasticsearch with user-controlled hosts — SSRF via Elasticsearch
    return elasticsearch.Elasticsearch(hosts)


def couch_connect(url: str):
    # SRC-108: couchdb.Server with user-controlled URL — SSRF via CouchDB
    return couchdb.Server(url)


import pty  # noqa: E402

import pexpect  # noqa: E402


def run_pty(cmd: str) -> None:
    # SRC-109: pty.spawn with user-controlled command — OS command execution via PTY
    pty.spawn(cmd)


def run_pexpect(cmd: str):
    # SRC-110: pexpect.spawn with user-controlled command — OS command execution via pexpect
    return pexpect.spawn(cmd)


def run_in_cwd(cwd: str) -> None:
    # SRC-111: subprocess.Popen with user-controlled cwd — directory traversal in cwd
    subprocess.Popen(["ls"], cwd=cwd)


import psycopg2  # noqa: E402
import pymysql  # noqa: E402
import redis  # noqa: E402


def connect_redis(host: str):
    # SRC-112: redis.Redis(host=user_host) — SSRF via user-controlled Redis host
    return redis.Redis(host=host, port=6379)


def connect_mysql(host: str):
    # SRC-113: pymysql.connect(host=user_host) — SSRF via MySQL host
    return pymysql.connect(host=host, user="root", password="secret", db="app")


def connect_postgres(host: str):
    # SRC-114: psycopg2.connect(host=user_host) — SSRF via PostgreSQL host
    return psycopg2.connect(host=host, dbname="app", user="admin", password="secret")


import httpx  # noqa: E402


async def run_async_prog(prog: str) -> None:
    # SRC-115: asyncio.create_subprocess_exec with user-controlled program
    await asyncio.create_subprocess_exec(prog, "--help")


async def open_tcp(host: str) -> None:
    # SRC-116: asyncio.open_connection with user-controlled host — SSRF
    await asyncio.open_connection(host, 8080)


def stream_url(url: str) -> None:
    # SRC-117: httpx.stream(method, url) — SSRF via user-controlled URL
    with httpx.stream("GET", url) as _r:  # noqa: F841
        pass


import aiofiles  # noqa: E402
import boto3  # noqa: E402


def create_boto3_client(endpoint_url: str):
    # SRC-118: boto3.client with user-controlled endpoint_url — SSRF
    return boto3.client("s3", endpoint_url=endpoint_url)


async def read_file_async(path: str) -> str:
    # SRC-119: aiofiles.open with user-controlled path — async path traversal
    async with aiofiles.open(path, "r") as f:
        return await f.read()


def run_in_env(env: dict) -> None:
    # SRC-120: subprocess.Popen(env=user_env) — user-controlled environment dict
    subprocess.Popen(["app"], env=env)


import celery  # noqa: E402
import kafka  # noqa: E402
import motor.motor_asyncio  # noqa: E402


async def get_motor_client(url: str):
    # SRC-121: AsyncIOMotorClient with user-controlled URL — SSRF
    return motor.motor_asyncio.AsyncIOMotorClient(url)


def get_kafka_producer(bootstrap_servers: str):
    # SRC-122: KafkaProducer with user-controlled bootstrap_servers — SSRF
    return kafka.KafkaProducer(bootstrap_servers=bootstrap_servers)


def get_celery_app(broker: str):
    # SRC-123: Celery with user-controlled broker URL — SSRF
    return celery.Celery(broker=broker)


import clickhouse_driver  # noqa: E402
import influxdb_client  # noqa: E402
import neo4j  # noqa: E402


def get_influx_client(url: str):
    # SRC-124: InfluxDBClient with user-controlled URL — SSRF
    return influxdb_client.InfluxDBClient(url=url)


def get_clickhouse_client(host: str):
    # SRC-125: clickhouse_driver.Client with user-controlled host — SSRF
    return clickhouse_driver.Client(host=host)


def get_neo4j_driver(uri: str):
    # SRC-126: GraphDatabase.driver with user-controlled URI — SSRF
    return neo4j.GraphDatabase.driver(uri)
