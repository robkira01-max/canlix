"""AST-based security analyzer for Python MCP server source files."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from mcpprobe.models import Confidence, Severity, SourceFinding

_KEY_PREFIXES = re.compile(
    r"^(sk-[A-Za-z0-9]{32,}"
    r"|ghp_[A-Za-z0-9]{36,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|xox[bpoa]-[A-Za-z0-9\-]+"
    r"|ya29\.[A-Za-z0-9_\-]+"
    r"|AIza[A-Za-z0-9_\-]{35}"
    r")"
)
_SECRET_VARNAMES = re.compile(
    r"(?i)(api[_-]?key|apikey|secret|password|passwd|token|auth_token|credential|private[_-]?key|access[_-]?key)"
)
_SHELL_FUNCS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
}
_HTTP_CLIENT_FUNCS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.request",
    "requests.head",
    "requests.options",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.patch",
    "httpx.request",
    "urlopen",
    "urllib.request.urlopen",
}
_REDIRECT_FUNCS = {
    "redirect",
    "flask.redirect",
    "werkzeug.utils.redirect",
    "fastapi.responses.RedirectResponse",
    "starlette.responses.RedirectResponse",
}
_PATH_IO_FUNCS = {
    "open",
    "Path",  # Path(user_path) — entry point for pathlib traversal
    "os.path.exists",
    "os.path.isfile",
    "os.path.isdir",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "shutil.copy",
    "shutil.move",
    "shutil.rmtree",
}
# SQL method suffixes — matches cursor.execute, db.execute, session.execute, etc.
_SQL_METHODS = frozenset({".execute", ".executemany", ".executescript", ".query", ".raw"})

# SRC-010: insecure PRNG — random module functions that must not be used for crypto
_INSECURE_RANDOM_FUNCS = frozenset(
    {
        "random.random",
        "random.randint",
        "random.randrange",
        "random.choice",
        "random.choices",
        "random.shuffle",
        "random.sample",
        "random.uniform",
        "random.gauss",
    }
)
# SRC-019: unsafe deserialization beyond pickle (marshal, shelve, jsonpickle, dill)
_UNSAFE_DESER_FUNCS = frozenset(
    {
        "marshal.loads",
        "marshal.load",
        "shelve.open",
        "jsonpickle.decode",
        "dill.loads",
        "dill.load",
        "dill.loads",
        "ruamel.yaml.load",
    }
)
# SRC-020: hardcoded cryptographic key/IV passed to cipher constructor
_CIPHER_FUNCS = frozenset(
    {
        "AES.new",
        "ARC4.new",
        "DES.new",
        "DES3.new",
        "Blowfish.new",
        "Cipher",
        "Fernet",
        "cryptography.fernet.Fernet",
        "cryptography.hazmat.primitives.ciphers.Cipher",
    }
)
# SRC-021: CORS wildcard — FastAPI / Starlette / Flask-CORS allow_origins=["*"]
_CORS_MIDDLEWARE_FUNCS = frozenset(
    {
        "CORSMiddleware",
        "CORS",
        "app.add_middleware",
    }
)
# SRC-028: insecure random seed — random.seed() with a fixed/constant value
# A fixed seed makes the PRNG sequence fully predictable.
_FIXED_SEED_TYPES = (int, float, str, bytes)
# SRC-031: insecure temporary file — mktemp() exposes a TOCTOU race condition
_TEMPFILE_UNSAFE_FUNCS = frozenset({"tempfile.mktemp"})
# SRC-032: hardcoded JWT secret — jwt.encode/decode with a string literal as key
_JWT_SIGN_FUNCS = frozenset({"jwt.encode", "jwt.decode", "jose.jwt.encode", "jose.jwt.decode"})
# SRC-033: deprecated TLS protocol constants (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
_WEAK_TLS_PROTOCOLS = frozenset({"PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"})
# SRC-038: world-writable permission bits (os.chmod with mode & 0o002 set)
_WORLD_WRITE_BIT = 0o002
# SRC-039: base64 used as obfuscation on security-sensitive values
_BASE64_FUNCS = frozenset({"base64.b64decode", "base64.b64encode", "base64.decodebytes", "base64.encodebytes"})
# SRC-041: credentials embedded in connection-string URL
_CRED_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z+\-.]*://[^@\s:\"']{1,64}:[^@\s\"']{4,64}@", re.IGNORECASE)
# SRC-042: marshal deserialization — arbitrary code execution
_MARSHAL_FUNCS = frozenset({"marshal.loads", "marshal.load"})
# SRC-045: file serving with user-controlled path
_SEND_FILE_FUNCS = frozenset({"send_file", "flask.send_file", "send_from_directory", "flask.send_from_directory"})
# SRC-047: dynamic module loading with user-controlled name
_IMPORT_MODULE_FUNCS = frozenset({"importlib.import_module", "import_module", "__import__"})
# SRC-048: archive extraction without path filter — zip/tar slip
_EXTRACTALL_PARENTS = frozenset({"zipfile.ZipFile", "tarfile.open", "tarfile.TarFile", "ZipFile", "TarFile"})
# SRC-050: dynamic native library loading with user-controlled path — arbitrary code execution
_CTYPES_LOAD_FUNCS = frozenset({"ctypes.CDLL", "ctypes.cdll.LoadLibrary", "ctypes.WinDLL", "ctypes.OleDLL"})
# SRC-051: threading.Thread with user-controlled target — arbitrary callable execution
_THREAD_FUNCS = frozenset({"threading.Thread", "Thread"})
# SRC-052: getattr with user-controlled attribute name — arbitrary attribute access
# SRC-053: os.environ.update/setdefault with user-controlled dict — environment injection
_ENV_UPDATE_FUNCS = frozenset({"os.environ.update", "os.putenv"})
# SRC-054: xmlrpc.client.ServerProxy with user-controlled URL — SSRF via XML-RPC
_XMLRPC_FUNCS = frozenset({"xmlrpc.client.ServerProxy", "xmlrpc.client.Transport", "ServerProxy"})
# SRC-055: Flask render_template_string with user-controlled template — SSTI
_RENDER_TEMPLATE_STRING_FUNCS = frozenset({"render_template_string", "flask.render_template_string"})
# SRC-056: multiprocessing.Process with user-controlled target — arbitrary subprocess
_PROCESS_FUNCS = frozenset({"multiprocessing.Process", "Process"})
# SRC-057: webbrowser.open with user-controlled URL — open redirect in OS browser
_WEBBROWSER_FUNCS = frozenset({"webbrowser.open", "webbrowser.open_new", "webbrowser.open_new_tab"})
# SRC-058: ftplib.FTP / FTP_TLS with user-controlled host — SSRF via FTP, plaintext credentials
_FTP_FUNCS = frozenset({"ftplib.FTP", "ftplib.FTP_TLS", "FTP", "FTP_TLS"})
# SRC-059: smtplib.SMTP / SMTP_SSL with user-controlled host — open relay / SSRF
_SMTP_FUNCS = frozenset({"smtplib.SMTP", "smtplib.SMTP_SSL", "smtplib.LMTP", "SMTP", "SMTP_SSL"})
# SRC-060: ldap3.Server / ldap.initialize with user-controlled host — LDAP injection / SSRF
_LDAP_FUNCS = frozenset({"ldap3.Server", "ldap.initialize", "ldap3.Connection", "Server"})
# SRC-061: os.popen() with user-controlled command — shell injection
_OS_POPEN_FUNCS = frozenset({"os.popen", "popen"})
# SRC-062: urllib.request.Request / urlopen with user-controlled URL — SSRF
_URLLIB_REQUEST_FUNCS = frozenset({"urllib.request.Request", "urllib.request.urlretrieve", "urlretrieve"})
# SRC-063: zipimport.zipimporter with user-controlled path — arbitrary zip code import
_ZIPIMPORT_FUNCS = frozenset({"zipimport.zipimporter", "zipimporter"})
# SRC-066: asyncio.create_subprocess_shell with user-controlled command — async shell injection
_ASYNC_SHELL_FUNCS = frozenset({"asyncio.create_subprocess_shell", "create_subprocess_shell"})
# SRC-067: socket.create_connection with user-controlled host in address tuple — SSRF
_SOCKET_CONNECT_FUNCS = frozenset({"socket.create_connection", "create_connection"})
# SRC-068: hashlib.pbkdf2_hmac with user-controlled iteration count — DoS via CPU exhaustion
# SRC-069: subprocess.Popen / subprocess.run with user-controlled `executable` kwarg
# SRC-070: subprocess.getoutput / getstatusoutput with user-controlled cmd — shell injection
_GETOUTPUT_FUNCS = frozenset({"subprocess.getoutput", "subprocess.getstatusoutput", "getoutput", "getstatusoutput"})
# SRC-072: send_from_directory with user-controlled directory path — directory escape
_SEND_FROM_DIR_FUNCS = frozenset({"send_from_directory", "flask.send_from_directory"})
# SRC-029: password hashed with fast algorithm (sha256/sha512 instead of bcrypt/argon2)
_FAST_HASH_FUNCS = frozenset(
    {
        "hashlib.sha256",
        "hashlib.sha512",
        "hashlib.sha1",
        "hashlib.md5",
        "hashlib.sha3_256",
        "hashlib.sha3_512",
        "sha256",
        "sha512",
    }
)
# Access-control names that should never be used in assert statements
_AUTH_NAMES = frozenset(
    {
        "is_authenticated",
        "is_admin",
        "is_superuser",
        "has_role",
        "is_authorized",
        "require_auth",
        "authenticated",
        "authorized",
    }
)
# SRC-025: security-header removal — explicit deletion/override of a security header
_SECURITY_HEADER_NAMES = frozenset(
    {
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
    }
)
# SRC-026: mass assignment — Model(**param) where param comes from function args
_ORM_MODEL_NAMES = frozenset(
    {
        "Model",
        "User",
        "Item",
        "Record",
        "Entry",
        "Document",
        "Session",
    }
)
# SRC-027: path.join / os.path.join with user-controlled segment
_PATH_JOIN_FUNCS = frozenset({"os.path.join", "Path"})
# SRC-022: server-side template injection — Template constructed from user input
_TEMPLATE_RENDER_FUNCS = frozenset(
    {
        "Template",
        "jinja2.Template",
        "mako.template.Template",
        "string.Template",
        "env.get_template",
        "jinja2.Environment.get_template",
    }
)
# SRC-023: user-controlled regex — re.compile/search/match/fullmatch with param from func args
_REGEX_COMPILE_FUNCS = frozenset(
    {
        "re.compile",
        "re.search",
        "re.match",
        "re.fullmatch",
        "re.findall",
        "re.finditer",
        "re.sub",
        "re.split",
    }
)
# SRC-024: sensitive data logged — logging call with security-sensitive keyword in format string
_LOG_FUNCS = frozenset(
    {
        "logging.debug",
        "logging.info",
        "logging.warning",
        "logging.error",
        "logging.critical",
        "logger.debug",
        "logger.info",
        "logger.warning",
        "logger.error",
        "logger.critical",
        "log.debug",
        "log.info",
        "log.warning",
        "log.error",
        "log.critical",
    }
)
# SRC-018: XML parsers vulnerable to entity expansion (XXE)
# Includes both full module paths and common import-alias forms (import ET as ET, etc.)
_XML_PARSE_FUNCS = frozenset(
    {
        # Full dotted paths
        "xml.etree.ElementTree.parse",
        "xml.etree.ElementTree.fromstring",
        "xml.etree.ElementTree.iterparse",
        "xml.etree.cElementTree.parse",
        "xml.etree.cElementTree.fromstring",
        "minidom.parse",
        "minidom.parseString",
        "xml.dom.minidom.parse",
        "xml.dom.minidom.parseString",
        "lxml.etree.fromstring",
        "lxml.etree.parse",
        # Common alias forms — import xml.etree.ElementTree as ET, from lxml import etree
        "ET.fromstring",
        "ET.parse",
        "ET.iterparse",
        "ElementTree.fromstring",
        "ElementTree.parse",
        "etree.fromstring",
        "etree.parse",
    }
)
# Words that indicate a security-sensitive identifier (checked after splitting on '_')
_SECURITY_WORDS = frozenset(
    {
        "token",
        "secret",
        "password",
        "passwd",
        "nonce",
        "salt",
        "otp",
        "pin",
        "session",
        "key",
        "auth",
        "credential",
    }
)


def _is_security_name(name: str) -> bool:
    """Return True if any underscore-separated part of name is security-sensitive."""
    return bool(set(name.lower().split("_")) & _SECURITY_WORDS)


class _Visitor(ast.NodeVisitor):
    def __init__(self, lines: list[str], path: Path) -> None:
        self.findings: list[SourceFinding] = []
        self.lines = lines
        self.path = path
        self._param_names: set[str] = set()  # current function's parameter names
        self._current_func_name: str = ""  # current function's name (for SRC-010 return check)
        self._defusedxml_aliases: set[str] = set()  # local names that alias defusedxml (safe)

    def _snip(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def _add(
        self,
        rule_id: str,
        severity: Severity,
        confidence: Confidence,
        lineno: int,
        message: str,
        remediation: str,
    ) -> None:
        self.findings.append(
            SourceFinding(
                rule_id=rule_id,
                severity=severity,
                confidence=confidence,
                file_path=self.path,
                line_number=lineno,
                message=message,
                code_snippet=self._snip(lineno),
                remediation=remediation,
            )
        )

    def _has_param_in_expr(self, node: ast.expr) -> bool:
        """Return True if node directly references a function parameter."""
        if isinstance(node, ast.Name):
            return node.id in self._param_names
        if isinstance(node, ast.JoinedStr):  # f-string
            return any(isinstance(v, ast.FormattedValue) and self._has_param_in_expr(v.value) for v in node.values)
        if isinstance(node, ast.BinOp):  # + or %
            return self._has_param_in_expr(node.left) or self._has_param_in_expr(node.right)
        return False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if "defusedxml" in alias.name:
                local = alias.asname if alias.asname else alias.name.rsplit(".", 1)[-1]
                self._defusedxml_aliases.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and "defusedxml" in node.module:
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                self._defusedxml_aliases.add(local)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old_params = self._param_names
        old_func = self._current_func_name
        args = node.args
        params: set[str] = {a.arg for a in args.args + args.posonlyargs + args.kwonlyargs}
        if args.vararg:
            params.add(args.vararg.arg)
        if args.kwarg:
            params.add(args.kwarg.arg)
        self._param_names = params
        self._current_func_name = node.name
        self.generic_visit(node)
        self._param_names = old_params
        self._current_func_name = old_func

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            # del response.headers["strict-transport-security"]
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.slice, ast.Constant)
                and isinstance(target.slice.value, str)
                and target.slice.value.lower() in _SECURITY_HEADER_NAMES
            ):
                self._add(
                    "SRC-025",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"Security header '{target.slice.value}' explicitly removed — browsers lose protection",
                    "Never delete security headers. Set them via middleware; do not remove them per-route.",
                )
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        def _has_auth_check(expr: ast.expr) -> bool:
            if isinstance(expr, ast.Attribute) and expr.attr in _AUTH_NAMES:
                return True
            if isinstance(expr, ast.Name) and expr.id in _AUTH_NAMES:
                return True
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr in _AUTH_NAMES:
                return True
            if isinstance(expr, ast.BoolOp):
                return any(_has_auth_check(v) for v in expr.values)
            if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
                return _has_auth_check(expr.operand)
            return False

        if _has_auth_check(node.test):
            self._add(
                "SRC-030",
                Severity.HIGH,
                Confidence.MEDIUM,
                node.lineno,
                "assert used for access control — Python -O flag disables all assertions at runtime",
                "Replace assert with an explicit if/raise. Use @login_required or raise HTTPException(403).",
            )
        self.generic_visit(node)

    def _func_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        # 3-level: urllib.request.urlopen
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute)
            and isinstance(node.func.value.value, ast.Name)
        ):
            return f"{node.func.value.value.id}.{node.func.value.attr}.{node.func.attr}"
        return ""

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            if _KEY_PREFIXES.match(node.value):
                self._add(
                    "SRC-001",
                    Severity.CRITICAL,
                    Confidence.HIGH,
                    node.lineno,
                    "Hardcoded API key or token detected in source code",
                    "Move secret to an environment variable or secrets manager. Never commit credentials.",
                )
            # SRC-041: credentials embedded in a connection-string URL
            if _CRED_URL_RE.search(node.value):
                self._add(
                    "SRC-041",
                    Severity.CRITICAL,
                    Confidence.HIGH,
                    node.lineno,
                    "Credentials embedded in connection-string URL — password visible in source and logs",
                    "Use environment variables for the user/password components and build the URL at runtime.",
                )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value
            if len(val) >= 16 and not _KEY_PREFIXES.match(val):
                for target in node.targets:
                    if isinstance(target, ast.Name) and _SECRET_VARNAMES.search(target.id):
                        self._add(
                            "SRC-001",
                            Severity.HIGH,
                            Confidence.MEDIUM,
                            node.lineno,
                            f"Potential secret in variable '{target.id}' — value looks like a credential",
                            "Use os.environ.get() or a secrets manager instead of hardcoding.",
                        )

        # SRC-010: insecure PRNG assigned to a security-sensitive variable
        if isinstance(node.value, ast.Call) and self._func_name(node.value) in _INSECURE_RANDOM_FUNCS:
            for target in node.targets:
                if isinstance(target, ast.Name) and _is_security_name(target.id):
                    self._add(
                        "SRC-010",
                        Severity.MEDIUM,
                        Confidence.MEDIUM,
                        node.lineno,
                        f"Insecure PRNG: random.* assigned to '{target.id}' — not suitable for cryptographic use",
                        "Use secrets.token_hex(), secrets.token_bytes(), or os.urandom() for security tokens.",
                    )
                    break

        # SRC-014: debug mode enabled — DEBUG = True (or truthy constant)
        if isinstance(node.value, ast.Constant) and node.value.value is True:
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.upper() in ("DEBUG", "DEBUG_MODE", "FLASK_DEBUG"):
                    self._add(
                        "SRC-014",
                        Severity.MEDIUM,
                        Confidence.HIGH,
                        node.lineno,
                        f"'{target.id} = True' enables debug mode — must not be True in production",
                        "Set DEBUG via environment variable: DEBUG = os.environ.get('DEBUG', 'false') == 'true'.",
                    )

        # SRC-044: HTTP header injection — user-controlled value written directly to response.headers[key]
        if self._param_names and isinstance(node.value, ast.Name) and node.value.id in self._param_names:
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Attribute)
                    and target.value.attr == "headers"
                ):
                    self._add(
                        "SRC-044",
                        Severity.MEDIUM,
                        Confidence.MEDIUM,
                        node.lineno,
                        f"response.headers[key] = {node.value.id} — user-controlled value allows CRLF injection",
                        "Strip CR/LF from header values. Never write raw user input to response headers.",
                    )
                    break

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        # SRC-013: timing-safe comparison — == or != with a security-sensitive name
        # Only fire when neither side is a constant (literal comparisons like `== ""` are benign)
        for op in node.ops:
            if isinstance(op, (ast.Eq, ast.NotEq)):
                operands = [node.left] + node.comparators
                if any(isinstance(o, ast.Constant) for o in operands):
                    continue
                for operand in operands:
                    if isinstance(operand, ast.Name) and _is_security_name(operand.id):
                        self._add(
                            "SRC-013",
                            Severity.MEDIUM,
                            Confidence.MEDIUM,
                            node.lineno,
                            f"Non-constant-time comparison on '{operand.id}' — vulnerable to timing attacks",
                            "Use hmac.compare_digest(a, b) for secret/token comparisons to prevent timing attacks.",
                        )
                        break
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        # SRC-010: random.* returned from a security-sensitive function
        if (
            node.value
            and isinstance(node.value, ast.Call)
            and self._func_name(node.value) in _INSECURE_RANDOM_FUNCS
            and _is_security_name(self._current_func_name)
        ):
            self._add(
                "SRC-010",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                node.lineno,
                f"Insecure PRNG: random.* in '{self._current_func_name}' — not suitable for cryptographic use",
                "Use secrets.token_hex(), secrets.token_bytes(), or os.urandom() for security tokens.",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        fname = self._func_name(node)

        if fname in ("eval", "exec"):
            self._add(
                "SRC-002",
                Severity.HIGH,
                Confidence.HIGH,
                node.lineno,
                f"Use of '{fname}()' allows arbitrary code execution",
                f"Remove {fname}(). Replace with explicit logic or ast.literal_eval() for safe parsing.",
            )

        elif fname in _SHELL_FUNCS:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add(
                        "SRC-003",
                        Severity.HIGH,
                        Confidence.HIGH,
                        node.lineno,
                        f"'{fname}(shell=True)' enables command injection via unsanitised input",
                        "Use shell=False and pass args as a list: subprocess.run(['cmd', 'arg']).",
                    )

        elif fname in ("os.system", "os.popen"):
            self._add(
                "SRC-004",
                Severity.HIGH,
                Confidence.HIGH,
                node.lineno,
                f"'{fname}()' is a command injection risk",
                "Replace with subprocess.run(['cmd', 'arg'], shell=False).",
            )

        elif fname in ("pickle.loads", "pickle.load"):
            self._add(
                "SRC-005",
                Severity.MEDIUM,
                Confidence.HIGH,
                node.lineno,
                "pickle deserialization executes arbitrary code on untrusted data",
                "Avoid pickle for untrusted input. Use json, msgpack, or protobuf instead.",
            )

        elif fname == "yaml.load":
            has_loader = any(kw.arg == "Loader" for kw in node.keywords)
            if not has_loader:
                self._add(
                    "SRC-006",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    "yaml.load() without Loader= can execute arbitrary Python objects",
                    "Replace with yaml.safe_load() or pass Loader=yaml.SafeLoader.",
                )
            else:
                # SRC-034: yaml.load() with an explicitly unsafe Loader
                _UNSAFE_YAML_LOADERS = {"Loader", "FullLoader", "UnsafeLoader"}
                for kw in node.keywords:
                    if kw.arg == "Loader" and isinstance(kw.value, ast.Attribute):
                        if kw.value.attr in _UNSAFE_YAML_LOADERS:
                            self._add(
                                "SRC-034",
                                Severity.MEDIUM,
                                Confidence.HIGH,
                                node.lineno,
                                f"yaml.load(Loader=yaml.{kw.value.attr}) can deserialise arbitrary Python objects",
                                "Use yaml.safe_load() or Loader=yaml.SafeLoader. FullLoader and Loader are unsafe.",
                            )
                        break

        if fname in _HTTP_CLIENT_FUNCS and self._param_names:
            url_node: ast.expr | None = None
            if node.args:
                url_node = node.args[0]
            else:
                for kw in node.keywords:
                    if kw.arg == "url":
                        url_node = kw.value
                        break
            if url_node and isinstance(url_node, ast.Name) and url_node.id in self._param_names:
                self._add(
                    "SRC-007",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"HTTP request with URL from function parameter '{url_node.id}' — SSRF risk",
                    "Validate the URL against an allowlist. Never pass raw user-supplied URLs to HTTP clients.",
                )

        if fname in _PATH_IO_FUNCS and self._param_names:
            path_node: ast.expr | None = node.args[0] if node.args else None
            if path_node and isinstance(path_node, ast.Name) and path_node.id in self._param_names:
                self._add(
                    "SRC-008",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"File I/O with path from function parameter '{path_node.id}' — path traversal risk",
                    "Validate the path against an allowlist or use os.path.realpath + prefix check.",
                )

        if any(fname.endswith(m) for m in _SQL_METHODS) and self._param_names and node.args:
            if self._has_param_in_expr(node.args[0]):
                self._add(
                    "SRC-009",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    node.lineno,
                    "SQL query built from function parameter — SQL injection risk",
                    "Use parameterised queries: cursor.execute(sql, [params]). Never format SQL strings.",
                )

        # SRC-015: open redirect — redirect() with a URL from a function parameter
        if fname in _REDIRECT_FUNCS and self._param_names and node.args:
            url_arg = node.args[0]
            if isinstance(url_arg, ast.Name) and url_arg.id in self._param_names:
                self._add(
                    "SRC-015",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"Open redirect: redirect() with parameter '{url_arg.id}' — attacker-controlled URL",
                    "Validate the redirect URL against an allowlist. Never redirect to a raw user-supplied value.",
                )

        # SRC-018: XXE — unsafe XML parsing (stdlib parsers are vulnerable to entity expansion)
        # Matches both full dotted names and common import-alias forms (import ET as ET, etc.)
        # Excludes aliases that resolve to defusedxml (the patched, safe replacement).
        if fname in _XML_PARSE_FUNCS and fname.split(".", 1)[0] not in self._defusedxml_aliases:
            self._add(
                "SRC-018",
                Severity.HIGH,
                Confidence.HIGH,
                node.lineno,
                f"{fname}() is vulnerable to XXE — can read local files or trigger SSRF via entity expansion",
                "Replace with defusedxml.ElementTree or defusedxml.minidom. Never parse untrusted XML with stdlib.",
            )

        # SRC-017: insecure cookie — set_cookie() without httponly=True or secure=True
        if fname in ("response.set_cookie", "resp.set_cookie", "set_cookie"):
            has_httponly = any(
                kw.arg == "httponly" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            has_secure = any(
                kw.arg == "secure" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if not has_httponly:
                self._add(
                    "SRC-017",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    node.lineno,
                    "set_cookie() called without httponly=True — cookie accessible via JavaScript (XSS risk)",
                    "Add httponly=True to prevent client-side script access to the cookie.",
                )
            if not has_secure:
                self._add(
                    "SRC-017",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    node.lineno,
                    "set_cookie() called without secure=True — cookie sent over unencrypted HTTP",
                    "Add secure=True to ensure the cookie is only transmitted over HTTPS.",
                )

        # SRC-016: JWT algorithm confusion or disabled verification
        if fname in ("jwt.decode", "jose.jwt.decode", "python_jose.jwt.decode"):
            for kw in node.keywords:
                if kw.arg == "algorithms" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and str(elt.value).lower() == "none":
                            self._add(
                                "SRC-016",
                                Severity.HIGH,
                                Confidence.HIGH,
                                node.lineno,
                                "JWT decoded with algorithms=['none'] — allows unsigned tokens (auth bypass)",
                                "Specify a strong algorithm explicitly: algorithms=['HS256'] or ['RS256'].",
                            )
                            break
                elif kw.arg == "options" and isinstance(kw.value, ast.Dict):
                    for k, v in zip(kw.value.keys, kw.value.values):
                        if (
                            isinstance(k, ast.Constant)
                            and k.value == "verify_signature"
                            and isinstance(v, ast.Constant)
                            and v.value is False
                        ):
                            self._add(
                                "SRC-016",
                                Severity.HIGH,
                                Confidence.HIGH,
                                node.lineno,
                                "JWT signature verification disabled — tokens accepted without cryptographic check",
                                "Remove options={'verify_signature': False}. Always verify JWT signatures.",
                            )
                            break

        # SRC-012: weak hash algorithm — MD5 or SHA-1
        if fname in ("hashlib.md5", "hashlib.sha1"):
            self._add(
                "SRC-012",
                Severity.MEDIUM,
                Confidence.HIGH,
                node.lineno,
                f"{fname}() is cryptographically broken — do not use for security-sensitive hashing",
                "Use hashlib.sha256() or hashlib.sha3_256() for security. For passwords use bcrypt/argon2.",
            )
        elif fname == "hashlib.new" and node.args:
            first = node.args[0]
            if (
                isinstance(first, ast.Constant)
                and isinstance(first.value, str)
                and first.value.lower()
                in (
                    "md5",
                    "sha1",
                    "sha-1",
                )
            ):
                self._add(
                    "SRC-012",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"hashlib.new('{first.value}') uses a broken algorithm — do not use for security-sensitive hashing",
                    "Use hashlib.sha256() or hashlib.sha3_256() for security. For passwords use bcrypt/argon2.",
                )

        # SRC-011: TLS verification disabled — verify=False kwarg
        # SRC-065: ssl=False kwarg disables TLS in aiohttp / websockets
        for kw in node.keywords:
            if kw.arg == "ssl" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self._add(
                    "SRC-065",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    "ssl=False disables TLS certificate verification — allows MITM attacks",
                    "Remove ssl=False or pass an ssl.SSLContext with proper CA verification.",
                )
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self._add(
                    "SRC-011",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    "TLS certificate verification disabled (verify=False) — allows MITM attacks",
                    "Remove verify=False. Use certifi or the system CA bundle. Never disable TLS verification.",
                )
                break

        # SRC-011: ssl._create_unverified_context() explicitly bypasses certificate checks
        if fname in ("ssl._create_unverified_context",):
            self._add(
                "SRC-011",
                Severity.HIGH,
                Confidence.HIGH,
                node.lineno,
                "ssl._create_unverified_context() disables certificate verification — allows MITM attacks",
                "Use ssl.create_default_context() without modification to enforce certificate verification.",
            )

        # SRC-019: unsafe deserialization — marshal, shelve, jsonpickle, dill execute arbitrary code
        if fname in _UNSAFE_DESER_FUNCS:
            self._add(
                "SRC-019",
                Severity.HIGH,
                Confidence.HIGH,
                node.lineno,
                f"{fname}() deserializes arbitrary objects — attacker-controlled input can execute code",
                "Avoid these deserializers for untrusted data. Use json.loads() or a schema-validated format.",
            )

        # SRC-020: hardcoded key passed as literal to cipher constructor
        if fname in _CIPHER_FUNCS and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, (str, bytes)):
                self._add(
                    "SRC-020",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"Hardcoded cryptographic key passed to {fname}() — key material must not be in source",
                    "Load keys from environment variables or a secrets manager. Never hardcode crypto keys.",
                )

        # SRC-021: CORS wildcard — allow_origins=["*"] is dangerous when combined with credentials
        if fname in _CORS_MIDDLEWARE_FUNCS:
            for kw in node.keywords:
                if kw.arg == "allow_origins" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            self._add(
                                "SRC-021",
                                Severity.MEDIUM,
                                Confidence.HIGH,
                                node.lineno,
                                "CORS allow_origins=['*'] — any origin can make cross-origin requests",
                                "Restrict allowed origins to a known allowlist. Wildcard + credentials = auth bypass.",
                            )
                            break

        # SRC-022: SSTI — Template/jinja2.Template constructed from a function parameter
        if fname in _TEMPLATE_RENDER_FUNCS and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name) and first_arg.id in self._param_names:
                self._add(
                    "SRC-022",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"{fname}() constructed from user-controlled input — allows server-side template injection",
                    "Never render user-supplied strings as templates. Use a fixed template with safe context vars.",
                )

        # SRC-023: ReDoS — re.compile/search with user-controlled pattern
        if fname in _REGEX_COMPILE_FUNCS and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name) and first_arg.id in self._param_names:
                self._add(
                    "SRC-023",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"{fname}() called with user-controlled pattern — catastrophic backtracking (ReDoS) risk",
                    "Reject user-supplied patterns. If needed, enforce a length/complexity limit and use a timeout.",
                )

        # SRC-024: sensitive data logged — first arg is an f-string referencing a security-sensitive name
        if fname in _LOG_FUNCS and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.JoinedStr):
                for val in first_arg.values:
                    if (
                        isinstance(val, ast.FormattedValue)
                        and isinstance(val.value, ast.Name)
                        and _is_security_name(val.value.id)
                    ):
                        self._add(
                            "SRC-024",
                            Severity.MEDIUM,
                            Confidence.MEDIUM,
                            node.lineno,
                            f"Sensitive value '{val.value.id}' logged — credentials or tokens may appear in log files",
                            "Redact or mask secrets before logging. Never log raw tokens, passwords, or keys.",
                        )
                        break

        # SRC-026: mass assignment — Model(**param) where param is a function argument
        # In ast.Call, **expr is represented as keyword(arg=None, value=expr)
        for kw in node.keywords:
            if kw.arg is None and isinstance(kw.value, ast.Name) and kw.value.id in self._param_names:
                self._add(
                    "SRC-026",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"Mass assignment: **{kw.value.id} spreads untrusted data into a model/function call",
                    "Enumerate permitted fields explicitly. Use a schema (Pydantic, marshmallow) to filter input.",
                )
                break

        # SRC-027: path traversal via os.path.join/Path with user-controlled segment
        if fname in _PATH_JOIN_FUNCS and len(node.args) >= 2:
            if any(isinstance(a, ast.Name) and a.id in self._param_names for a in node.args[1:]):
                self._add(
                    "SRC-027",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"{fname}() with user-controlled segment — path traversal with '../' sequences possible",
                    "Resolve the joined path and assert it starts with the allowed base dir. Reject paths with '..'.",
                )

        # SRC-028: insecure PRNG seed — random.seed(constant) makes the sequence predictable
        if fname == "random.seed" and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, _FIXED_SEED_TYPES):
                self._add(
                    "SRC-028",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"random.seed({first_arg.value!r}) — fixed seed makes PRNG output fully predictable",
                    "Call random.seed() without arguments (uses OS entropy) or use secrets module instead.",
                )

        # SRC-029: password hashed with a fast algorithm — not suitable for password storage
        # Check for hashlib.sha256(password) or hashlib.sha256(password.encode(...))
        if fname in _FAST_HASH_FUNCS and node.args:
            first_arg = node.args[0]
            # Direct name: sha256(password)
            sec_name = None
            if isinstance(first_arg, ast.Name) and _is_security_name(first_arg.id):
                sec_name = first_arg.id
            # Method call on name: sha256(password.encode())
            elif (
                isinstance(first_arg, ast.Call)
                and isinstance(first_arg.func, ast.Attribute)
                and isinstance(first_arg.func.value, ast.Name)
                and _is_security_name(first_arg.func.value.id)
            ):
                sec_name = first_arg.func.value.id
            if sec_name:
                self._add(
                    "SRC-029",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"{fname}({sec_name}) — fast hash algorithms are not suitable for password storage",
                    "Use bcrypt, argon2-cffi, or hashlib.scrypt for password hashing. Never use SHA/MD5.",
                )

        # SRC-031: tempfile.mktemp() — TOCTOU race between name creation and file open
        if fname in _TEMPFILE_UNSAFE_FUNCS:
            self._add(
                "SRC-031",
                Severity.MEDIUM,
                Confidence.HIGH,
                node.lineno,
                "tempfile.mktemp() has a TOCTOU race — another process can create the file between name and open",
                "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() which atomically create the file.",
            )

        # SRC-032: hardcoded JWT secret — string literal as the key argument
        if fname in _JWT_SIGN_FUNCS and len(node.args) >= 2:
            key_arg = node.args[1]
            if isinstance(key_arg, ast.Constant) and isinstance(key_arg.value, str):
                self._add(
                    "SRC-032",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"Hardcoded JWT secret in {fname}() — key material must not be in source code",
                    "Load the JWT secret from os.environ. Never hardcode cryptographic secrets.",
                )

        # SRC-033: weak TLS protocol — SSLContext with a deprecated protocol constant
        if fname == "ssl.SSLContext" and node.args:
            proto = node.args[0]
            if isinstance(proto, ast.Attribute) and proto.attr in _WEAK_TLS_PROTOCOLS:
                self._add(
                    "SRC-033",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"ssl.SSLContext(ssl.{proto.attr}) uses a deprecated protocol vulnerable to known attacks",
                    "Use ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) with minimum_version=ssl.TLSVersion.TLSv1_2.",
                )

        # SRC-035: hardcoded fallback in os.environ.get() — secret leaks into source
        if fname == "os.environ.get" and len(node.args) >= 2:
            key_arg, default_arg = node.args[0], node.args[1]
            if (
                isinstance(key_arg, ast.Constant)
                and isinstance(key_arg.value, str)
                and _SECRET_VARNAMES.search(key_arg.value)
                and isinstance(default_arg, ast.Constant)
                and isinstance(default_arg.value, str)
                and len(default_arg.value) > 4
            ):
                self._add(
                    "SRC-035",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"os.environ.get('{key_arg.value}', '<literal>') — hardcoded fallback exposes secret in source",
                    "Remove the fallback or use a safe empty default. Load secrets exclusively from the environment.",
                )

        # SRC-037: subprocess with user-controlled executable — command injection without shell=True
        if fname in _SHELL_FUNCS and node.args and self._param_names:
            first_arg = node.args[0]
            if (
                isinstance(first_arg, ast.List)
                and first_arg.elts
                and isinstance(first_arg.elts[0], ast.Name)
                and first_arg.elts[0].id in self._param_names
            ):
                self._add(
                    "SRC-037",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"{fname}([{first_arg.elts[0].id}, ...]) — user-controlled executable allows OS command injection",
                    "Validate the command against an allowlist. Never let callers control the executable name.",
                )

        # SRC-038: world-writable file permissions — os.chmod with o+w bit set
        if fname == "os.chmod" and len(node.args) >= 2:
            perm_node = node.args[1]
            if (
                isinstance(perm_node, ast.Constant)
                and isinstance(perm_node.value, int)
                and perm_node.value & _WORLD_WRITE_BIT
            ):
                self._add(
                    "SRC-038",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"os.chmod(path, 0o{perm_node.value:03o}) sets world-writable permissions on the file",
                    "Use restrictive permissions (e.g. 0o640 for files, 0o750 for dirs). Never grant o+w.",
                )

        # SRC-039: base64 used as encryption/obfuscation on a security-sensitive value
        if fname in _BASE64_FUNCS and node.args:
            first_arg = node.args[0]
            # Resolve security name: plain Name OR x.encode()/x.decode() pattern
            sec_name: str | None = None
            if isinstance(first_arg, ast.Name):
                sec_name = first_arg.id
            elif (
                isinstance(first_arg, ast.Call)
                and isinstance(first_arg.func, ast.Attribute)
                and isinstance(first_arg.func.value, ast.Name)
                and first_arg.func.attr in {"encode", "decode"}
            ):
                sec_name = first_arg.func.value.id
            if sec_name and _is_security_name(sec_name):
                self._add(
                    "SRC-039",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"{fname}({sec_name}) — base64 is encoding, not encryption; secrets remain recoverable",
                    "Use a proper encryption library (cryptography, Fernet) or a secrets manager instead.",
                )

        # SRC-036: open redirect — redirect() with URL taken directly from request data
        _REQUEST_DATA_GETTERS = frozenset(
            {
                "request.args.get",
                "request.form.get",
                "request.values.get",
                "request.json.get",
                "request.params.get",
            }
        )
        if fname in _REDIRECT_FUNCS and node.args:
            url_arg = node.args[0]
            if isinstance(url_arg, ast.Call) and self._func_name(url_arg) in _REQUEST_DATA_GETTERS:
                self._add(
                    "SRC-036",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    "Open redirect: URL taken directly from request data — attacker can redirect to any site",
                    "Validate the URL against an allowlist or use a safe relative path. Never trust raw request data.",
                )

        # SRC-043: SQL injection via .format() — cursor.execute("SELECT...{}".format(param))
        if any(fname.endswith(m) for m in _SQL_METHODS) and self._param_names and node.args:
            sql_arg = node.args[0]
            if (
                isinstance(sql_arg, ast.Call)
                and isinstance(sql_arg.func, ast.Attribute)
                and sql_arg.func.attr == "format"
                and any(isinstance(a, ast.Name) and a.id in self._param_names for a in sql_arg.args)
            ):
                self._add(
                    "SRC-043",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    "SQL query built with str.format() from function parameter — SQL injection risk",
                    "Use parameterised queries: cursor.execute(sql, [params]). Never format SQL strings.",
                )

        # SRC-045: flask.send_file / send_from_directory with user-controlled path
        if fname in _SEND_FILE_FUNCS and node.args:
            path_arg = node.args[0]
            if isinstance(path_arg, ast.Name) and path_arg.id in self._param_names:
                self._add(
                    "SRC-045",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"{fname}({path_arg.id}) — user-controlled path allows reading any file on the server",
                    "Validate the path against an allowlist or use send_from_directory with a fixed base dir.",
                )

        # SRC-040: compile() with user-controlled source — dynamic bytecode compilation
        if fname == "compile" and node.args:
            first_arg = node.args[0]
            if not isinstance(first_arg, ast.Constant):
                self._add(
                    "SRC-040",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    node.lineno,
                    "compile() with dynamic source — runtime compilation of untrusted code allows code injection",
                    "Never compile user-supplied strings. Use ast.literal_eval() for data, or a safe DSL library.",
                )

        # SRC-042: marshal.loads() — unsafe deserialization (arbitrary code execution via crafted bytes)
        if fname in _MARSHAL_FUNCS and node.args:
            first_arg = node.args[0]
            if not isinstance(first_arg, ast.Constant):
                self._add(
                    "SRC-042",
                    Severity.CRITICAL,
                    Confidence.HIGH,
                    node.lineno,
                    f"{fname}() deserializes untrusted bytes — a crafted payload executes arbitrary Python code",
                    "Never deserialize marshal data from untrusted sources. Use json or a schema-validated format.",
                )

        # SRC-046: hashlib.new() with user-controlled algorithm name — algorithm confusion / weak hash
        if fname == "hashlib.new" and node.args and self._param_names:
            algo_arg = node.args[0]
            if isinstance(algo_arg, ast.Name) and algo_arg.id in self._param_names:
                self._add(
                    "SRC-046",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"hashlib.new({algo_arg.id}) — user-controlled algorithm name enables algorithm confusion",
                    "Allowlist the hash algorithm: assert algo in {'sha256', 'sha3_256'} before calling hashlib.new().",
                )

        # SRC-047: importlib.import_module() with user-controlled name — module injection
        if fname in _IMPORT_MODULE_FUNCS and node.args and self._param_names:
            mod_arg = node.args[0]
            if isinstance(mod_arg, ast.Name) and mod_arg.id in self._param_names:
                self._add(
                    "SRC-047",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"{fname}({mod_arg.id}) — user-controlled module name allows loading arbitrary code",
                    "Allowlist permitted module names before calling import_module().",
                )

        # SRC-048: archive extractall() without filter — zip/tar path traversal (zip slip)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "extractall"
            and not any(kw.arg == "filter" for kw in node.keywords)
        ):
            self._add(
                "SRC-048",
                Severity.HIGH,
                Confidence.MEDIUM,
                node.lineno,
                "extractall() without a path filter allows zip/tar slip — entries can overwrite arbitrary files",
                "Pass filter='data' (Python 3.12+) or validate each member path against the target directory.",
            )

        # SRC-049: socket.setdefaulttimeout(None) — infinite timeout, DoS risk
        if fname == "socket.setdefaulttimeout" and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and first_arg.value is None:
                self._add(
                    "SRC-049",
                    Severity.LOW,
                    Confidence.HIGH,
                    node.lineno,
                    "socket.setdefaulttimeout(None) removes all timeouts — a stalled peer causes indefinite hang",
                    "Set a finite timeout (e.g. socket.setdefaulttimeout(30)) or use per-socket timeouts.",
                )

        # SRC-050: ctypes.CDLL / LoadLibrary with user-controlled path — loads arbitrary native code
        if fname in _CTYPES_LOAD_FUNCS and node.args and self._param_names:
            lib_arg = node.args[0]
            if isinstance(lib_arg, ast.Name) and lib_arg.id in self._param_names:
                self._add(
                    "SRC-050",
                    Severity.CRITICAL,
                    Confidence.HIGH,
                    node.lineno,
                    f"{fname}({lib_arg.id}) — user-controlled library path executes arbitrary native code",
                    "Never pass user input to ctypes loaders. Allowlist permitted library paths.",
                )

        # SRC-051: threading.Thread(target=param) — user-controlled callable executed in a thread
        if fname in _THREAD_FUNCS and self._param_names:
            target_kw = next((kw for kw in node.keywords if kw.arg == "target"), None)
            if target_kw and isinstance(target_kw.value, ast.Name) and target_kw.value.id in self._param_names:
                self._add(
                    "SRC-051",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"Thread(target={target_kw.value.id}) — user-controlled callable executed in a new thread",
                    "Never pass user-supplied callables to Thread(target=). Use a fixed, allowlisted function.",
                )

        # SRC-064: setattr(obj, name, val) with user-controlled attribute name — attribute injection
        if fname == "setattr" and len(node.args) >= 2 and self._param_names:
            attr_arg = node.args[1]
            if isinstance(attr_arg, ast.Name) and attr_arg.id in self._param_names:
                self._add(
                    "SRC-064",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"setattr(obj, {attr_arg.id}, ...) — user-controlled attribute name enables attribute injection",
                    "Allowlist permitted attribute names before calling setattr().",
                )

        # SRC-052: getattr(obj, param) — user-controlled attribute name exposes arbitrary attribute access
        if fname == "getattr" and len(node.args) >= 2 and self._param_names:
            attr_arg = node.args[1]
            if isinstance(attr_arg, ast.Name) and attr_arg.id in self._param_names:
                self._add(
                    "SRC-052",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    node.lineno,
                    f"getattr(obj, {attr_arg.id}) — user-controlled attribute name allows accessing "
                    "private attributes or dunder methods",
                    "Allowlist permitted attribute names before calling getattr().",
                )

        # SRC-053: os.environ.update(param) — user-controlled dict overwrites environment variables
        if fname in _ENV_UPDATE_FUNCS and node.args and self._param_names:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name) and first_arg.id in self._param_names:
                self._add(
                    "SRC-053",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"{fname}({first_arg.id}) — user-controlled data overwrites process environment variables",
                    "Never update os.environ from untrusted input. Environment variables affect the whole process.",
                )

        # SRC-054: xmlrpc.client.ServerProxy with user-controlled URL — SSRF via XML-RPC
        if fname in _XMLRPC_FUNCS and node.args and self._param_names:
            url_arg = node.args[0]
            if isinstance(url_arg, ast.Name) and url_arg.id in self._param_names:
                self._add(
                    "SRC-054",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"xmlrpc.client.ServerProxy({url_arg.id}) — user-controlled URL allows SSRF via XML-RPC",
                    "Validate the URL against an allowlist of permitted hosts before creating a ServerProxy.",
                )

        # SRC-055: render_template_string(param) — Flask SSTI via user-controlled template string
        if fname in _RENDER_TEMPLATE_STRING_FUNCS and node.args and self._param_names:
            tmpl_arg = node.args[0]
            if isinstance(tmpl_arg, ast.Name) and tmpl_arg.id in self._param_names:
                self._add(
                    "SRC-055",
                    Severity.CRITICAL,
                    Confidence.HIGH,
                    node.lineno,
                    f"render_template_string({tmpl_arg.id}) — user-controlled template enables SSTI "
                    "(arbitrary code execution via Jinja2)",
                    "Never render user-supplied strings as templates. Use render_template() with static files.",
                )

        # SRC-056: multiprocessing.Process(target=param) — user-controlled callable in subprocess
        if fname in _PROCESS_FUNCS and self._param_names:
            target_kw = next((kw for kw in node.keywords if kw.arg == "target"), None)
            if target_kw and isinstance(target_kw.value, ast.Name) and target_kw.value.id in self._param_names:
                self._add(
                    "SRC-056",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"Process(target={target_kw.value.id}) — user-controlled callable launched as a subprocess",
                    "Never pass user-supplied callables to Process(target=). Use a fixed, allowlisted function.",
                )

        # SRC-057: webbrowser.open(param) — user-controlled URL opens OS browser (open redirect)
        if fname in _WEBBROWSER_FUNCS and node.args and self._param_names:
            url_arg = node.args[0]
            if isinstance(url_arg, ast.Name) and url_arg.id in self._param_names:
                self._add(
                    "SRC-057",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"webbrowser.open({url_arg.id}) — user-controlled URL opens the OS browser "
                    "(open redirect / phishing risk)",
                    "Validate the URL against an allowlist before calling webbrowser.open().",
                )

        # SRC-061: os.popen(cmd) with user-controlled command — shell injection
        if fname in _OS_POPEN_FUNCS and node.args and self._param_names:
            cmd_arg = node.args[0]
            if self._has_param_in_expr(cmd_arg):
                self._add(
                    "SRC-061",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    "os.popen() with user-controlled command — arbitrary shell command execution",
                    "Use subprocess.run() with a list of arguments and shell=False. Never pass user input to popen().",
                )

        # SRC-062: urllib.request.Request / urlretrieve with user-controlled URL — SSRF
        if fname in _URLLIB_REQUEST_FUNCS and node.args and self._param_names:
            url_arg = node.args[0]
            if isinstance(url_arg, ast.Name) and url_arg.id in self._param_names:
                self._add(
                    "SRC-062",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"{fname}({url_arg.id}) — user-controlled URL enables SSRF via urllib",
                    "Validate the URL against an allowlist of permitted hosts before making the request.",
                )

        # SRC-070: subprocess.getoutput(cmd) with user-controlled cmd — shell injection
        if fname in _GETOUTPUT_FUNCS and node.args and self._param_names:
            cmd_arg = node.args[0]
            if self._has_param_in_expr(cmd_arg):
                self._add(
                    "SRC-070",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    "subprocess.getoutput() with user-controlled command — arbitrary shell command execution",
                    "Use subprocess.run() with shell=False and an args list. getoutput() runs commands via shell.",
                )

        # SRC-071: logging.basicConfig(filename=user_path) — log file path control
        if fname == "logging.basicConfig" and self._param_names:
            fn_kw = next((k for k in node.keywords if k.arg == "filename"), None)
            if fn_kw and isinstance(fn_kw.value, ast.Name) and fn_kw.value.id in self._param_names:
                self._add(
                    "SRC-071",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"logging.basicConfig(filename={fn_kw.value.id}) — user controls the log file path",
                    "Hardcode the log file path in configuration. Never allow callers to control the log destination.",
                )

        # SRC-072: send_from_directory(user_dir, filename) — user-controlled base directory
        if fname in _SEND_FROM_DIR_FUNCS and node.args and self._param_names:
            dir_arg = node.args[0]
            if isinstance(dir_arg, ast.Name) and dir_arg.id in self._param_names:
                self._add(
                    "SRC-072",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"send_from_directory({dir_arg.id}, ...) — user-controlled base dir allows serving any file",
                    "Hardcode the base directory. Only the filename argument should ever come from user input.",
                )

        # SRC-067: socket.create_connection((host, port)) — user-controlled host in address tuple
        if fname in _SOCKET_CONNECT_FUNCS and node.args and self._param_names:
            addr_arg = node.args[0]
            if (
                isinstance(addr_arg, ast.Tuple)
                and addr_arg.elts
                and isinstance(addr_arg.elts[0], ast.Name)
                and addr_arg.elts[0].id in self._param_names
            ):
                self._add(
                    "SRC-067",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"socket.create_connection(({addr_arg.elts[0].id}, ...)) — user-controlled host enables SSRF",
                    "Allowlist permitted hosts before opening raw TCP connections.",
                )

        # SRC-068: hashlib.pbkdf2_hmac with user-controlled iteration count — DoS
        if fname == "hashlib.pbkdf2_hmac" and self._param_names:
            iter_arg: ast.expr | None = None
            if len(node.args) >= 4:
                iter_arg = node.args[3]
            else:
                kw = next((k for k in node.keywords if k.arg == "iterations"), None)
                if kw:
                    iter_arg = kw.value
            if iter_arg is not None and isinstance(iter_arg, ast.Name) and iter_arg.id in self._param_names:
                self._add(
                    "SRC-068",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"hashlib.pbkdf2_hmac(..., iterations={iter_arg.id}) — user controls KDF cost (DoS via CPU)",
                    "Cap iterations to a sane maximum (e.g. ≤ 600000) before calling pbkdf2_hmac().",
                )

        # SRC-069: subprocess.Popen / run with user-controlled executable= kwarg — command hijack
        if fname in _SHELL_FUNCS and self._param_names:
            exe_kw = next((k for k in node.keywords if k.arg == "executable"), None)
            if exe_kw and isinstance(exe_kw.value, ast.Name) and exe_kw.value.id in self._param_names:
                self._add(
                    "SRC-069",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"{fname}(executable={exe_kw.value.id}) — user-controlled executable overrides the binary",
                    "Hardcode the executable path. Never allow callers to override subprocess.executable.",
                )

        # SRC-066: asyncio.create_subprocess_shell(cmd) with user-controlled cmd — async shell injection
        if fname in _ASYNC_SHELL_FUNCS and node.args and self._param_names:
            cmd_arg = node.args[0]
            if self._has_param_in_expr(cmd_arg):
                self._add(
                    "SRC-066",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    "asyncio.create_subprocess_shell() with user-controlled command — async shell injection",
                    "Use create_subprocess_exec() with a fixed binary and args list. Never pass user input to shell.",
                )

        # SRC-063: zipimport.zipimporter(path) with user-controlled path — arbitrary zip code import
        if fname in _ZIPIMPORT_FUNCS and node.args and self._param_names:
            path_arg = node.args[0]
            if isinstance(path_arg, ast.Name) and path_arg.id in self._param_names:
                self._add(
                    "SRC-063",
                    Severity.HIGH,
                    Confidence.HIGH,
                    node.lineno,
                    f"zipimport.zipimporter({path_arg.id}) — user-controlled path imports code from arbitrary zips",
                    "Never allow callers to control the path passed to zipimporter(). Allowlist permitted archives.",
                )

        # SRC-058: ftplib.FTP(host) with user-controlled host — SSRF via FTP
        if fname in _FTP_FUNCS and node.args and self._param_names:
            host_arg = node.args[0]
            if isinstance(host_arg, ast.Name) and host_arg.id in self._param_names:
                self._add(
                    "SRC-058",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"ftplib.FTP({host_arg.id}) — user-controlled FTP host enables SSRF; credentials sent in cleartext",
                    "Allowlist FTP host values. Never connect to arbitrary user-supplied hosts.",
                )

        # SRC-059: smtplib.SMTP(host) with user-controlled host — open relay / SSRF
        if fname in _SMTP_FUNCS and node.args and self._param_names:
            host_arg = node.args[0]
            if isinstance(host_arg, ast.Name) and host_arg.id in self._param_names:
                self._add(
                    "SRC-059",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"smtplib.SMTP({host_arg.id}) — user-controlled SMTP host allows SSRF and email relay abuse",
                    "Hardcode the SMTP host in configuration. Never let callers supply the mail server address.",
                )

        # SRC-060: ldap3.Server(host) / ldap.initialize(url) with user-controlled value — LDAP SSRF
        if fname in _LDAP_FUNCS and node.args and self._param_names:
            host_arg = node.args[0]
            if isinstance(host_arg, ast.Name) and host_arg.id in self._param_names:
                self._add(
                    "SRC-060",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    node.lineno,
                    f"{fname}({host_arg.id}) — user-controlled LDAP host enables SSRF and directory injection",
                    "Hardcode the LDAP server URL in configuration. Never allow callers to choose the directory host.",
                )

        self.generic_visit(node)


def analyze_python(path: Path) -> list[SourceFinding]:
    """Parse a Python file and return security findings."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []
    lines = source.splitlines()
    visitor = _Visitor(lines, path)
    visitor.visit(tree)
    return visitor.findings
