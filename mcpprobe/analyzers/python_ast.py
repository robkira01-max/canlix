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
        if isinstance(node.value, str) and _KEY_PREFIXES.match(node.value):
            self._add(
                "SRC-001",
                Severity.CRITICAL,
                Confidence.HIGH,
                node.lineno,
                "Hardcoded API key or token detected in source code",
                "Move secret to an environment variable or secrets manager. Never commit credentials.",
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
        for kw in node.keywords:
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
