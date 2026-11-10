"""Regex-based security analyzer for TypeScript/JavaScript MCP server source files.

Does not require Node.js or any external parser — pure Python regex line scanning.
"""

from __future__ import annotations

import re
from pathlib import Path

from mcpprobe.models import Confidence, Severity, SourceFinding

# ---------------------------------------------------------------------------
# TS-001a: key-prefix secrets in string literals (CRITICAL)
# ---------------------------------------------------------------------------

_KEY_PREFIX = re.compile(
    r"""(?x)
    ["'`]
    (
        sk-[A-Za-z0-9]{32,}
        | ghp_[A-Za-z0-9]{36,}
        | ghs_[A-Za-z0-9]{36,}
        | AKIA[0-9A-Z]{16}
        | xox[bpoa]-[A-Za-z0-9\-]+
        | ya29\.[A-Za-z0-9_\-]+
        | AIza[A-Za-z0-9_\-]{35}
        | eyJ[A-Za-z0-9_\-]{40,}   # JWT (long base64url header)
    )
    ["'`]
    """,
)

# ---------------------------------------------------------------------------
# TS-001b: variable-name heuristic (HIGH)
# ---------------------------------------------------------------------------

_SECRET_ASSIGN = re.compile(
    r"""(?x)
    (?:const|let|var|export\s+const)\s+
    ([A-Za-z_$][A-Za-z0-9_$]*)        # variable name
    (?:\s*:\s*\w+)?                     # optional TypeScript type annotation
    \s*=\s*
    ["']([^"']{16,})["']               # string value >= 16 chars (not env lookup)
    """,
)
_SECRET_VARNAMES = re.compile(
    r"(?i)(api[_-]?key|apikey|secret|password|passwd|token|auth_token|credential|private[_-]?key|access[_-]?key)"
)

# ---------------------------------------------------------------------------
# TS-002: eval() — arbitrary code execution
# ---------------------------------------------------------------------------

_EVAL = re.compile(r"\beval\s*\(")

# ---------------------------------------------------------------------------
# TS-003: execSync() — always shell, can't pass shell=False
# ---------------------------------------------------------------------------

_EXEC_SYNC = re.compile(r"\bexecSync\s*\(")

# ---------------------------------------------------------------------------
# TS-004: shell: true in spawn/exec options
# ---------------------------------------------------------------------------

_SHELL_TRUE = re.compile(r"\bshell\s*:\s*true\b")

# ---------------------------------------------------------------------------
# TS-005: exec() with template literal — interpolation enables injection
# ---------------------------------------------------------------------------

_EXEC_TEMPLATE = re.compile(r"\bexec\s*\(\s*`")

# ---------------------------------------------------------------------------
# TS-006: prototype pollution — __proto__ assignment
# ---------------------------------------------------------------------------

_PROTO_POLLUTION = re.compile(
    r"""(?x)
    __proto__\s*[=\[]
    | \.constructor\s*\[\s*["']prototype["']
    """,
)

# ---------------------------------------------------------------------------
# TS-012: weak hash algorithm — MD5 or SHA-1 passed to crypto.createHash
# ---------------------------------------------------------------------------

_WEAK_HASH = re.compile(
    r"""(?x)
    crypto\.createHash\s*\(\s*["'](md5|sha-?1)["']   # crypto.createHash('md5') / ('sha1') / ('sha-1')
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-011: TLS verification disabled
# ---------------------------------------------------------------------------

# rejectUnauthorized: false — in any options object (https.request, tls.connect, etc.)
_TLS_REJECT_FALSE = re.compile(r"\brejectUnauthorized\s*:\s*false\b")
# NODE_TLS_REJECT_UNAUTHORIZED set to "0" or 0 at runtime
_TLS_ENV_ZERO = re.compile(r"""NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?""")

# ---------------------------------------------------------------------------
# TS-018: XXE — unsafe XML parsing via DOMParser or similar
# ---------------------------------------------------------------------------

_XXE_DOM_PARSER = re.compile(
    r"""(?x)
    new\s+DOMParser\s*\(\s*\)\.parseFromString\s*\(\s*[A-Za-z_$]  # new DOMParser().parseFromString(var
    | \bparseFromString\s*\(\s*[A-Za-z_$]                           # parser.parseFromString(var
    | new\s+JSDOM\s*\(\s*[A-Za-z_$]                                 # new JSDOM(var
    | xmldom\.DOMParser\s*\(\s*\)\.parseFromString                   # xmldom.DOMParser().parseFromString
    """,
)
# Skip when the first arg is a plain string literal
_XXE_LITERAL_SAFE = re.compile(r"""parseFromString\s*\(\s*["'`]|new\s+JSDOM\s*\(\s*["'`]""")

# ---------------------------------------------------------------------------
# TS-017: insecure cookie — res.cookie() without httpOnly or secure flags
# ---------------------------------------------------------------------------

# Detects res.cookie("name", value, { ... }) where the options object is present
_COOKIE_SET = re.compile(
    r"""(?x)
    res\.cookie\s*\(                   # res.cookie(
    | response\.cookie\s*\(            # response.cookie(
    | ctx\.cookies\.set\s*\(           # Koa ctx.cookies.set(
    """,
)
_COOKIE_HTTPONLY_TRUE = re.compile(r"\bhttpOnly\s*:\s*true\b", re.IGNORECASE)
_COOKIE_SECURE_TRUE = re.compile(r"\bsecure\s*:\s*true\b")

# ---------------------------------------------------------------------------
# TS-016: JWT algorithm confusion or disabled verification
# ---------------------------------------------------------------------------

_JWT_ALGO_NONE = re.compile(
    r"""(?x)
    algorithms\s*:\s*\[[^\]]*["']none["'][^\]]*\]  # algorithms: ['none'] or ["none"]
    | verify_signature\s*:\s*false\b                 # verify_signature: false
    | ignoreExpiration\s*:\s*true\b                  # ignoreExpiration: true (weakens JWT security)
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-015: open redirect — location / res.redirect with a non-literal URL
# ---------------------------------------------------------------------------

_OPEN_REDIRECT = re.compile(
    r"""(?x)
    window\.location(?:\.href)?\s*=\s*[A-Za-z_$]      # window.location[.href] = variable
    | res\.redirect\s*\(\s*[A-Za-z_$]                   # res.redirect(variable
    | response\.redirect\s*\(\s*[A-Za-z_$]              # response.redirect(variable
    | router\.navigate\s*\(\s*[A-Za-z_$]                # Angular router.navigate(variable
    | next\s*\(\s*['"]?redirect['"]\s*,\s*[A-Za-z_$]   # next('redirect', variable)
    """,
)
# Skip lines where the URL is clearly a literal string
_REDIRECT_LITERAL = re.compile(r"""(?:\.redirect|\.href|\.location)\s*\(?[= ]*["'`/]""")

# ---------------------------------------------------------------------------
# TS-014: debug mode hardcoded — NODE_ENV="development" or DEBUG=true in source
# ---------------------------------------------------------------------------

_DEBUG_NODE_ENV = re.compile(
    r"""(?x)
    NODE_ENV\s*[=:]\s*["']development["']   # NODE_ENV = "development" (assignment or object prop)
    | NODE_ENV\s*[=:]\s*["']dev["']          # NODE_ENV = "dev"
    """,
)
_DEBUG_TRUE = re.compile(
    r"""(?x)
    (?:const|let|var|export\s+const)\s+
    (?:DEBUG|debug|DEBUG_MODE|FLASK_DEBUG)   # variable name
    \s*(?::\s*\w+\s*)?=\s*true\b             # = true (TypeScript/JS boolean)
    """,
)

# ---------------------------------------------------------------------------
# TS-013: timing-safe comparison — === / !== with security-sensitive names
# ---------------------------------------------------------------------------

# Security variable names relevant for timing-attack detection.
# No leading \b so camelCase suffixes (storedToken, userPassword) are matched;
# trailing \b prevents matching tokenizer, protocol, etc.
_TS_SEC_VAR_TIMING = re.compile(
    r"""(?i)(?:token|secret|password|passwd|nonce|salt|api_?key|auth_?key|private_?key|otp|pin|session_?token)\b"""
)
# Any equality/inequality operator: == === != !==
# Pattern: one char from [!=] followed by 1-2 '=' chars  =>  matches ==, ===, !=, !==
_TS_EQ_OP = re.compile(r"[!=]={1,2}")
# Lines where one side of the comparison is a literal/null/undefined/true/false — these are benign
_TS_LITERAL_SIDE = re.compile(
    r"""(?x)
    # equality op immediately before a literal/null/undefined/true/false (rhs)
    [!=]={1,2}\s*(?:["'`\d]|null\b|undefined\b|true\b|false\b)
    # equality op immediately after a literal/null/undefined/true/false (lhs)
    | (?:["'`\d]|null\b|undefined\b|true\b|false\b)\s*[!=]={1,2}
    """,
)

# ---------------------------------------------------------------------------
# TS-010: insecure PRNG — Math.random() in a security-sensitive context
# ---------------------------------------------------------------------------

_MATH_RANDOM = re.compile(r"\bMath\.random\s*\(\s*\)")
# Checks whether the line contains a security-sensitive name (token, secret, etc.)
_TS_SECURITY_CONTEXT = re.compile(
    r"(?i)\b(?:token|secret|password|passwd|nonce|salt|otp|session_id|private_key|api_key|auth_key|pin)\b",
)

# ---------------------------------------------------------------------------
# TS-009: SQL injection — template literal in DB query/execute call
# ---------------------------------------------------------------------------

_SQL_TEMPLATE = re.compile(
    r"""(?x)
    \.(?:query|execute|raw|run|exec)\s*\(\s*`[^`]*\$\{  # .query(`...${
    | \bknex\s*\.\s*raw\s*\(\s*`[^`]*\$\{               # knex.raw(`...${
    | \bsequelize\s*\.\s*query\s*\(\s*`[^`]*\$\{         # sequelize.query(`...${
    """,
)

# ---------------------------------------------------------------------------
# TS-008: path traversal — fs I/O with non-literal path argument
# ---------------------------------------------------------------------------

_PATH_FS = re.compile(
    r"""(?x)
    \bfs\.readFile(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.writeFile(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.appendFile(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.unlink(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.open(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.stat(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.rmdir(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.rm(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfsp\.readFile\s*\(\s*[A-Za-z_$]
    | \bfsp\.writeFile\s*\(\s*[A-Za-z_$]
    """,
)
_PATH_FS_LITERAL_SAFE = re.compile(r"""\bfs\.\w+\s*\(\s*["'`][^"'`]""")

# ---------------------------------------------------------------------------
# TS-007: SSRF — fetch/axios/got with non-literal URL argument
# ---------------------------------------------------------------------------

_SSRF_FETCH = re.compile(
    r"""(?x)
    \bfetch\s*\(\s*[A-Za-z_$]          # fetch(variable
    | \baxios\.[a-z]+\s*\(\s*[A-Za-z_$]  # axios.get(variable
    | \bgot\s*\(\s*[A-Za-z_$]           # got(variable
    | \bneedle\.[a-z]+\s*\(\s*[A-Za-z_$]  # needle.get(variable
    """,
)
# Negation: skip lines where the argument is a plain https?:// string (definitely safe)
_SSRF_LITERAL_SAFE = re.compile(r"""\bfetch\s*\(\s*["'`]https?://""")
_SSRF_AXIOS_LITERAL_SAFE = re.compile(r"""\baxios\.[a-z]+\s*\(\s*["'`]https?://""")


# ---------------------------------------------------------------------------
# TS-019: unsafe deserialization — node-serialize / serialize-javascript eval
# ---------------------------------------------------------------------------

_UNSAFE_DESERIALIZE = re.compile(
    r"""(?x)
    \bserialize\.unserialize\s*\(                        # node-serialize
    | \bunserialize\s*\(\s*[A-Za-z_$]                    # bare unserialize(variable
    | \beval\s*\(\s*JSON\.parse\s*\(                      # eval(JSON.parse(...))
    | \.fromJSON\s*\(\s*[A-Za-z_$]                        # .fromJSON(variable)
    """,
)

# ---------------------------------------------------------------------------
# TS-020: hardcoded cryptographic key/IV — string literal passed to createCipheriv
# ---------------------------------------------------------------------------

_HARDCODED_CRYPTO_KEY = re.compile(
    r"""(?x)
    createCipheriv\s*\(\s*["'`][^"'`]+["'`]\s*,\s*["'`]  # createCipheriv("aes-256-gcm", "hardcoded
    | createDecipheriv\s*\(\s*["'`][^"'`]+["'`]\s*,\s*["'`]  # createDecipheriv("aes-256-gcm", "hardcoded
    """,
)

# ---------------------------------------------------------------------------
# TS-021: CORS wildcard — Access-Control-Allow-Origin: * or cors({origin: "*"})
# ---------------------------------------------------------------------------

_CORS_WILDCARD = re.compile(
    r"""(?x)
    setHeader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']  # setHeader("ACAO", "*")
    | cors\s*\(\s*\{[^}]*origin\s*:\s*["']\*["']                            # cors({ origin: "*" })
    | ["']Access-Control-Allow-Origin["']\s*:\s*["']\*["']                  # object literal "ACAO": "*"
    """,
)


# ---------------------------------------------------------------------------
# TS-022: SSTI — template engine called with user-supplied template string
# ---------------------------------------------------------------------------

_SSTI_TEMPLATE = re.compile(
    r"""(?x)
    \bejs\.render\s*\(\s*[A-Za-z_$]              # ejs.render(variable
    | \bhandlebars\.compile\s*\(\s*[A-Za-z_$]     # handlebars.compile(variable
    | \bHandlebars\.compile\s*\(\s*[A-Za-z_$]     # Handlebars.compile(variable
    | \bnunjucks\.renderString\s*\(\s*[A-Za-z_$]  # nunjucks.renderString(variable
    | \bpug\.render\s*\(\s*[A-Za-z_$]             # pug.render(variable
    """,
)
_SSTI_LITERAL_SAFE = re.compile(r"""ejs\.render\s*\(\s*["'`]|\.compile\s*\(\s*["'`]""")

# ---------------------------------------------------------------------------
# TS-023: ReDoS — new RegExp() with a non-literal pattern
# ---------------------------------------------------------------------------

_REDOS_REGEXP = re.compile(
    r"""(?x)
    \bnew\s+RegExp\s*\(\s*[A-Za-z_$]   # new RegExp(variable
    """,
)
_REDOS_LITERAL_SAFE = re.compile(r"""\bnew\s+RegExp\s*\(\s*["'`/]""")

# ---------------------------------------------------------------------------
# TS-024: sensitive data in console.log / logger calls
# ---------------------------------------------------------------------------

_LOG_CALL = re.compile(
    r"""(?x)
    \bconsole\.(?:log|debug|info|warn|error)\s*\(   # console.log(
    | \blogger\.(?:log|debug|info|warn|error)\s*\(   # logger.log(
    | \bwinston\.(?:log|debug|info|warn|error)\s*\(  # winston.log(
    """,
)
_LOG_SENSITIVE_NAME = re.compile(
    r"""(?i)(?:token|secret|password|passwd|api_?key|private_?key|auth_?key|otp|pin|session_?id)\b"""
)


# ---------------------------------------------------------------------------
# TS-028: fixed PRNG seed — seedrandom/seedrandom-like with literal
# ---------------------------------------------------------------------------

_FIXED_SEED = re.compile(
    r"""(?x)
    \bseedrandom\s*\(\s*["'`\d]              # seedrandom("fixedSeed" or 42
    | Math\.random\s*\(\s*\)\s*;.*seed       # comment mentioning seed near Math.random
    """,
)

# ---------------------------------------------------------------------------
# TS-029: password hashed with a fast algorithm — createHash('sha256').update(password)
# ---------------------------------------------------------------------------

_FAST_HASH_PASSWORD = re.compile(
    r"""(?x)
    createHash\s*\(\s*["']sha(?:256|512|1|3-256|3-512)["']\s*\)\s*\.update\s*\(\s*
        (?:password|passwd|pwd|secret|credentials?)\b   # variable name is security-sensitive
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-030: assert used for access-control checks
# ---------------------------------------------------------------------------

_ASSERT_AUTH = re.compile(
    r"""(?x)
    \bassert\s*\(?\s*
        (?:[A-Za-z_$.]+\.)?
        (?:is(?:Admin|Authenticated|Authorized|Superuser)|hasRole|isLoggedIn|requiresAuth|authenticated)
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-025: security header explicitly removed / set to unsafe value
# ---------------------------------------------------------------------------

_SEC_HEADER_REMOVE = re.compile(
    r"""(?x)
    delete\s+(?:res|response|headers)\s*[\.\[]["']?
        (?:content-security-policy|x-frame-options|x-content-type-options|
           strict-transport-security|x-xss-protection)["']?\s*[\]\)]?  # delete res.headers["csp"]
    | removeHeader\s*\(\s*["']
        (?:content-security-policy|x-frame-options|x-content-type-options|
           strict-transport-security|x-xss-protection)["']            # .removeHeader("csp")
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-026: mass assignment — Object.assign(entity, req.body) or {...req.body}
# ---------------------------------------------------------------------------

_MASS_ASSIGN = re.compile(
    r"""(?x)
    Object\.assign\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*,\s*req\.body  # Object.assign(user, req.body)
    | \{\s*\.\.\.\s*req\.body                                           # { ...req.body }
    | \{\s*\.\.\.\s*request\.body                                       # { ...request.body }
    """,
)

# ---------------------------------------------------------------------------
# TS-027: path traversal via path.join with variable — user-controlled segment
# ---------------------------------------------------------------------------

_PATH_JOIN_VAR = re.compile(
    r"""(?x)
    \bpath\.join\s*\(\s*[^)]*,\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*\)   # path.join(base, variable)
    | \bpath\.resolve\s*\(\s*[^)]*,\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*\)  # path.resolve(base, variable)
    """,
)
_PATH_JOIN_LITERAL_SAFE = re.compile(
    r"""\bpath\.(?:join|resolve)\s*\(\s*["'`__][^,]+,\s*["'`]"""  # all literal args
)

# ---------------------------------------------------------------------------
# TS-031: sensitive value stored in localStorage / sessionStorage
# ---------------------------------------------------------------------------

_LOCAL_STORAGE_SENSITIVE = re.compile(
    r"""(?x)
    (?:localStorage|sessionStorage)\.setItem\s*\(\s*["']
    (?:token|secret|password|passwd|api_?key|private_?key|
       auth_?token|access_?token|session_?id|jwt|credentials?)
    ["']""",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-032: hardcoded JWT secret — string literal as key in jwt.sign / jwt.verify
# ---------------------------------------------------------------------------

_JWT_HARDCODED_SECRET = re.compile(
    r"""(?x)
    (?:jwt|jsonwebtoken)\.(?:sign|verify)\s*\(\s*
    \w[^,]*,\s*          # first argument (payload or token) + comma
    ["'][^"']{8,}["']    # second argument is a string literal of ≥ 8 chars
    """,
)

# ---------------------------------------------------------------------------
# TS-033: DOM XSS — innerHTML / outerHTML / document.write with variable input
# ---------------------------------------------------------------------------

_INNER_HTML_ASSIGN = re.compile(
    r"""(?x)
    \.innerHTML\s*\+?=\s*(?!["'`])   # .innerHTML = variable  or  .innerHTML += variable
    | \.outerHTML\s*\+?=\s*(?!["'`])
    | \bdocument\.write\s*\(\s*[A-Za-z_$]   # document.write(variable)
    | \bdocument\.writeln\s*\(\s*[A-Za-z_$]
    """,
)
_INNER_HTML_LITERAL_SAFE = re.compile(r"""\.(?:inner|outer)HTML\s*\+?=\s*["'`]""")

# ---------------------------------------------------------------------------
# TS-037: user-controlled executable in spawn / execFile — command injection
# ---------------------------------------------------------------------------

_SPAWN_VAR = re.compile(
    r"""(?x)
    \bspawn\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*      # spawn(variable
    | \bexecFile\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*  # execFile(variable
    | \bexecFileSync\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)
_SPAWN_LITERAL_SAFE = re.compile(
    r"""(?x)
    \bspawn\s*\(\s*["'`]
    | \bexecFile(?:Sync)?\s*\(\s*["'`]
    """,
)

# ---------------------------------------------------------------------------
# TS-038: world-writable file permissions — fs.chmod with 0o777 / 0777 / 777
# ---------------------------------------------------------------------------

_CHMOD_WORLD_WRITE = re.compile(
    r"""(?x)
    \bfs\.chmod(?:Sync)?\s*\([^,]+,\s*
    (?:0o?777|0777|511|0o?766|0o?776|0o?667|0o?676|0o?677|0o?666|438)
    \b
    """,
)

# ---------------------------------------------------------------------------
# TS-039: base64 used as encryption/obfuscation on a security-sensitive value
# ---------------------------------------------------------------------------

_BASE64_SENSITIVE = re.compile(
    r"""(?x)
    \batob\s*\(\s*(?:encoded)?(?:password|passwd|secret|token|api_?key|credential)
    | \bbtoa\s*\(\s*(?:password|passwd|secret|token|api_?key|credential)
    | Buffer\.from\s*\(\s*(?:password|passwd|secret|token|api_?key|credential)[^,]*,\s*["']base64["']
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-043: SQL injection via string concatenation in query/execute calls
# ---------------------------------------------------------------------------

_SQL_CONCAT_TS = re.compile(
    r"""(?x)
    \.(?:query|execute|raw|run|exec)\s*\(
    \s*(?:
        "[^"\n]*"\s*\+       # "SQL..." + variable  (double-quoted — no issue with inner ')
        | '[^'\n]*'\s*\+     # 'SQL...' + variable  (single-quoted — no issue with inner ")
        | [A-Za-z_$][A-Za-z0-9_$]*\s*\+\s*["']   # variable + "SQL..."
    )
    """,
)

# ---------------------------------------------------------------------------
# TS-044: HTTP header injection — user-controlled value written to setHeader/append
# ---------------------------------------------------------------------------

_HEADER_INJECT_TS = re.compile(
    r"""(?x)
    \bres\.(?:setHeader|append)\s*\(
    \s*["'`][^"'`\n]+["'`]\s*,\s*
    req\.(?:query|body|params|headers)\b
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-045: file serving with user-controlled path — res.sendFile / res.download from request
# ---------------------------------------------------------------------------

_SEND_FILE_FROM_REQ = re.compile(
    r"""(?x)
    \bres\.(?:sendFile|download)\s*\(\s*
    req\.(?:query|body|params)\b
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-055: crypto.randomBytes(userSize) — user-controlled allocation size, DoS risk
# ---------------------------------------------------------------------------

_RANDOM_BYTES_REQ = re.compile(
    r"""(?x)
    \bcrypto\.randomBytes\s*\(\s*
    (?:Number|parseInt|parseFloat)?\s*\(?\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-056: res.download() with user-controlled path — path traversal
# ---------------------------------------------------------------------------

_DOWNLOAD_FROM_REQ = re.compile(
    r"""(?x)
    \bres\.download\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-057: child_process.exec / exec() with direct request variable (not template literal)
# ---------------------------------------------------------------------------

_EXEC_VAR_REQ = re.compile(
    r"""(?x)
    \b(?:child_process\.exec|(?<![A-Za-z0-9_$])exec)\s*\(
    \s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-058: child_process.execFile(req.xxx) — user-controlled executable file path
# ---------------------------------------------------------------------------

_EXEC_FILE_REQ = re.compile(
    r"""(?x)
    \b(?:child_process\.execFile|(?<![A-Za-z0-9_$])execFile)\s*\(
    \s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-059: net.createConnection / net.connect with request data — raw TCP SSRF
# ---------------------------------------------------------------------------

_NET_CONNECT_REQ = re.compile(
    r"""(?x)
    \bnet\.(?:createConnection|connect)\s*\(
    [^)]*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-060: res.jsonp(req.xxx) — JSONP callback injection from request data
# ---------------------------------------------------------------------------

_JSONP_REQ = re.compile(
    r"""(?x)
    \bres\.jsonp\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-052: document.getElementById(req.xxx).innerHTML — DOM XSS via id injection
# ---------------------------------------------------------------------------

_DOM_ID_INJECT = re.compile(
    r"""(?x)
    document\.getElementById\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-053: fetch / axios with template literal URL containing request data — SSRF
# ---------------------------------------------------------------------------

_FETCH_TEMPLATE_REQ = re.compile(
    r"""(?x)
    \b(?:fetch|axios\.(?:get|post|put|delete|patch|request))\s*\(
    \s*`[^`]*\$\{req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*\}
    """,
)

# ---------------------------------------------------------------------------
# TS-054: localStorage.getItem() used as a trusted data source for security decisions
# ---------------------------------------------------------------------------

_LOCAL_STORAGE_TRUST = re.compile(
    r"""(?x)
    \blocalStorage\.getItem\s*\(\s*["'`](?:token|auth|session|user|role|permission|credential)[^"'`]*["'`]
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-049: setTimeout / setInterval with a variable (non-literal) as the callback
# ---------------------------------------------------------------------------

_SET_TIMEOUT_VAR = re.compile(
    r"""(?x)
    \bset(?:Timeout|Interval)\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*  # setTimeout(variable, ...)
    """,
)
_SET_TIMEOUT_LITERAL_SAFE = re.compile(
    r"""(?x)
    \bset(?:Timeout|Interval)\s*\(\s*(?:function\s*\(|(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>|\(\s*\)\s*=>)
    """,
)

# ---------------------------------------------------------------------------
# TS-050: process.exit() with user-controlled argument — denial of service
# ---------------------------------------------------------------------------

_PROCESS_EXIT_FROM_REQ = re.compile(
    r"""(?x)
    \bprocess\.exit\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-051: DOM open redirect — window.location / location.href set from request
# ---------------------------------------------------------------------------

_DOM_REDIRECT = re.compile(
    r"""(?x)
    (?:window\.location|location\.href)\s*=\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-046: fs.writeFile / fs.writeFileSync with user-controlled path from request
# ---------------------------------------------------------------------------

_WRITE_FILE_FROM_REQ = re.compile(
    r"""(?x)
    \bfs\.write(?:File|FileSync)\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-047: dynamic require() with a variable (non-literal) — module injection
# ---------------------------------------------------------------------------

_REQUIRE_VAR = re.compile(
    r"""(?x)
    \brequire\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*\)  # require(variable)
    """,
)
_REQUIRE_LITERAL_SAFE = re.compile(
    r"""(?x)
    \brequire\s*\(\s*["'`]  # require("literal") — static module name, safe
    """,
)

# ---------------------------------------------------------------------------
# TS-048: child_process.fork() with user-controlled script path
# ---------------------------------------------------------------------------

_FORK_FROM_REQ = re.compile(
    r"""(?x)
    \bchild_process\.fork\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    | \bfork\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-040: new Function() with dynamic argument — dynamic code execution (like eval for statements)
# ---------------------------------------------------------------------------

_NEW_FUNCTION_VAR = re.compile(
    r"""(?x)
    \bnew\s+Function\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*  # new Function(variable
    """,
)
_NEW_FUNCTION_LITERAL_SAFE = re.compile(
    r"""(?x)
    \bnew\s+Function\s*\(\s*["'`]  # new Function("literal" — static code, low risk
    """,
)

# ---------------------------------------------------------------------------
# TS-041: credentials embedded in a connection-string URL
# ---------------------------------------------------------------------------

_CRED_URL_TS = re.compile(
    r"""(?x)
    ["'`][a-zA-Z][a-zA-Z+\-.]*://[^@\s:'"` ]{1,64}:[^@\s'"` ]{4,64}@
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-042: vm.runInNewContext / vm.runInThisContext / vm.Script with variable
# ---------------------------------------------------------------------------

_VM_RUN_VAR = re.compile(
    r"""(?x)
    \bvm\.run(?:InNewContext|InThisContext|Script)\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*
    | \bnew\s+vm\.Script\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)
_VM_RUN_LITERAL_SAFE = re.compile(
    r"""(?x)
    \bvm\.run(?:InNewContext|InThisContext|Script)\s*\(\s*["'`]
    | \bnew\s+vm\.Script\s*\(\s*["'`]
    """,
)

# ---------------------------------------------------------------------------
# TS-034: unsafe YAML deserialisation — js-yaml .load() without schema
# ---------------------------------------------------------------------------

_YAML_LOAD_UNSAFE = re.compile(
    r"""(?x)
    \byaml\.load\s*\(\s*[A-Za-z_$]      # yaml.load(variable)
    | \bjsYaml\.load\s*\(\s*[A-Za-z_$]
    | \bYAML\.load\s*\(\s*[A-Za-z_$]
    """,
)
_YAML_LOAD_SAFE = re.compile(
    r"""(?x)
    \.safeLoad\s*\(              # yaml.safeLoad — legacy safe function
    | schema\s*:\s*\w+           # schema option passed
    """,
)

# ---------------------------------------------------------------------------
# TS-035: hardcoded fallback for environment variable with a sensitive name
# ---------------------------------------------------------------------------

_ENV_SENSITIVE_FALLBACK = re.compile(
    r"""(?x)
    \bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)   # process.env.VAR_NAME
    \s*(?:\?\?|\|\|)\s*                          # ?? or ||
    ["'][^"']{4,}["']                            # non-trivial string fallback
    """,
)
_ENV_SENSITIVE_VARNAME = re.compile(
    r"(?i)(api[_-]?key|apikey|secret|password|passwd|token|auth|credential|private[_-]?key)",
)

# ---------------------------------------------------------------------------
# TS-036: open redirect using request query / body / params directly
# ---------------------------------------------------------------------------

_REDIRECT_FROM_REQ = re.compile(
    r"""(?x)
    res\.redirect\s*\(\s*req\.(?:query|body|params)\b
    | response\.redirect\s*\(\s*request\.(?:query|body|params)\b
    | res\.redirect\s*\(\s*req\.(?:query|body|params)\.[A-Za-z_$]
    """,
)


def analyze_typescript(path: Path) -> list[SourceFinding]:
    """Scan a TypeScript/JavaScript file for security issues. Returns all findings."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[SourceFinding] = []
    lines = source.splitlines()

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        findings.extend(_scan_line(path, lineno, raw_line, line))

    return findings


def _scan_line(path: Path, lineno: int, raw: str, line: str) -> list[SourceFinding]:
    result: list[SourceFinding] = []
    reported: set[str] = set()

    def _add(rule_id: str, sev: Severity, conf: Confidence, msg: str, rem: str) -> None:
        if rule_id not in reported:
            reported.add(rule_id)
            result.append(
                SourceFinding(
                    rule_id=rule_id,
                    severity=sev,
                    confidence=conf,
                    file_path=path,
                    line_number=lineno,
                    message=msg,
                    code_snippet=line,
                    remediation=rem,
                )
            )

    # TS-001a: key prefix (CRITICAL — takes precedence over TS-001b)
    if _KEY_PREFIX.search(raw):
        _add(
            "TS-001",
            Severity.CRITICAL,
            Confidence.HIGH,
            "Hardcoded API key or token detected in source code",
            "Move secret to process.env.VAR_NAME or a secrets manager. Never commit credentials.",
        )
    else:
        # TS-001b: name-based heuristic (HIGH)
        m = _SECRET_ASSIGN.search(raw)
        if m and _SECRET_VARNAMES.search(m.group(1)):
            _add(
                "TS-001",
                Severity.HIGH,
                Confidence.MEDIUM,
                f"Potential secret in variable '{m.group(1)}' — value looks like a credential",
                "Use process.env.VAR_NAME instead of hardcoding secrets.",
            )

    # TS-002: eval
    if _EVAL.search(raw):
        _add(
            "TS-002",
            Severity.HIGH,
            Confidence.HIGH,
            "eval() allows arbitrary code execution",
            "Remove eval(). Use explicit logic or JSON.parse() for data parsing.",
        )

    # TS-003: execSync
    if _EXEC_SYNC.search(raw):
        _add(
            "TS-003",
            Severity.HIGH,
            Confidence.HIGH,
            "execSync() runs commands through the shell — command injection risk",
            "Use execFileSync(cmd, args) with a separate argument array to avoid shell interpretation.",
        )

    # TS-004: shell: true
    if _SHELL_TRUE.search(raw):
        _add(
            "TS-004",
            Severity.HIGH,
            Confidence.HIGH,
            "shell: true enables command injection via unsanitised input",
            "Remove shell: true. Pass command and arguments as separate array elements.",
        )

    # TS-005: exec with template literal
    if _EXEC_TEMPLATE.search(raw):
        _add(
            "TS-005",
            Severity.HIGH,
            Confidence.MEDIUM,
            "exec() with template literal — string interpolation enables command injection",
            "Use execFile(cmd, args) with an argument array. Never interpolate user input into shell commands.",
        )

    # TS-006: prototype pollution
    if _PROTO_POLLUTION.search(raw):
        _add(
            "TS-006",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "Potential prototype pollution — assignment to __proto__ or constructor.prototype",
            "Validate object keys before merging. Use Object.create(null) for untrusted data maps.",
        )

    # TS-007: SSRF — HTTP client with non-literal URL
    if _SSRF_FETCH.search(raw) and not _SSRF_LITERAL_SAFE.search(raw) and not _SSRF_AXIOS_LITERAL_SAFE.search(raw):
        _add(
            "TS-007",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "HTTP request with variable URL — SSRF risk",
            "Validate the URL against an allowlist. Never pass raw user-supplied URLs to HTTP clients.",
        )

    # TS-009: SQL injection — template literal in DB query
    if _SQL_TEMPLATE.search(raw):
        _add(
            "TS-009",
            Severity.HIGH,
            Confidence.MEDIUM,
            "SQL query built with template literal interpolation — SQL injection risk",
            "Use parameterised queries: db.query(sql, [params]). Never interpolate values into SQL.",
        )

    # TS-008: path traversal — fs I/O with non-literal path
    if _PATH_FS.search(raw) and not _PATH_FS_LITERAL_SAFE.search(raw):
        _add(
            "TS-008",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "File I/O with variable path — path traversal risk",
            "Validate the path with path.resolve() + a trusted prefix check before I/O operations.",
        )

    # TS-012: weak hash algorithm
    m012 = _WEAK_HASH.search(raw)
    if m012:
        algo = m012.group(1).lower()
        _add(
            "TS-012",
            Severity.MEDIUM,
            Confidence.HIGH,
            f"crypto.createHash('{algo}') uses a broken algorithm — do not use for security-sensitive hashing",
            "Use crypto.createHash('sha256') or 'sha3-256' for security. For passwords use bcrypt/argon2.",
        )

    # TS-011: TLS verification disabled
    if _TLS_REJECT_FALSE.search(raw) or _TLS_ENV_ZERO.search(raw):
        _add(
            "TS-011",
            Severity.HIGH,
            Confidence.HIGH,
            "TLS certificate verification disabled — allows MITM attacks",
            "Remove rejectUnauthorized: false. Never set NODE_TLS_REJECT_UNAUTHORIZED=0 in production.",
        )

    # TS-018: XXE — unsafe XML parsing with a non-literal input
    if _XXE_DOM_PARSER.search(raw) and not _XXE_LITERAL_SAFE.search(raw):
        _add(
            "TS-018",
            Severity.HIGH,
            Confidence.MEDIUM,
            "Unsafe XML parsing — DOMParser/JSDOM with variable input may be vulnerable to XXE",
            "Sanitise XML input before parsing. Disable external entity resolution if the parser supports it.",
        )

    # TS-017: insecure cookie — res.cookie() without httpOnly/secure on same line
    if _COOKIE_SET.search(raw):
        missing = []
        if not _COOKIE_HTTPONLY_TRUE.search(raw):
            missing.append("httpOnly: true")
        if not _COOKIE_SECURE_TRUE.search(raw):
            missing.append("secure: true")
        if missing:
            _add(
                "TS-017",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                f"Cookie set without {' and '.join(missing)} — vulnerable to XSS or plain-HTTP theft",
                "Always set { httpOnly: true, secure: true, sameSite: 'strict' } on session cookies.",
            )

    # TS-016: JWT algorithm confusion or disabled verification
    if _JWT_ALGO_NONE.search(raw):
        _add(
            "TS-016",
            Severity.HIGH,
            Confidence.HIGH,
            "JWT security weakened — 'none' algorithm or disabled verification allows auth bypass",
            "Use algorithms=['HS256'] or ['RS256']. Never set verify_signature: false in production.",
        )

    # TS-015: open redirect — location / res.redirect with a non-literal URL
    if _OPEN_REDIRECT.search(raw) and not _REDIRECT_LITERAL.search(raw):
        _add(
            "TS-015",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "Open redirect: URL set to a variable — attacker can redirect to a malicious site",
            "Validate the redirect URL against an allowlist. Never redirect to a raw user-supplied value.",
        )

    # TS-014: debug mode hardcoded in source
    if _DEBUG_NODE_ENV.search(raw) or _DEBUG_TRUE.search(raw):
        _add(
            "TS-014",
            Severity.MEDIUM,
            Confidence.HIGH,
            "Debug mode hardcoded in source — must not be enabled in production",
            "Read NODE_ENV / DEBUG from process.env at runtime; never hardcode 'development' or true.",
        )

    # TS-013: timing-safe comparison — ==, ===, !=, !== used on a security-sensitive name vs non-literal
    if _TS_EQ_OP.search(raw) and _TS_SEC_VAR_TIMING.search(raw) and not _TS_LITERAL_SIDE.search(raw):
        _add(
            "TS-013",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "Non-constant-time comparison on a security-sensitive name — vulnerable to timing attacks",
            "Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) to prevent timing-based secret leakage.",
        )

    # TS-010: insecure PRNG — Math.random() used in a security-sensitive context
    if _MATH_RANDOM.search(raw) and _TS_SECURITY_CONTEXT.search(raw):
        _add(
            "TS-010",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "Math.random() used in a security-sensitive context — not cryptographically secure",
            "Use crypto.getRandomValues() (browser) or crypto.randomBytes() (Node.js) for security tokens.",
        )

    # TS-019: unsafe deserialization — node-serialize / eval(JSON.parse()) patterns
    if _UNSAFE_DESERIALIZE.search(raw):
        _add(
            "TS-019",
            Severity.HIGH,
            Confidence.HIGH,
            "Unsafe deserialization — node-serialize or eval(JSON.parse()) can execute arbitrary code",
            "Use JSON.parse() with explicit validation. Never deserialize untrusted data with node-serialize.",
        )

    # TS-020: hardcoded cryptographic key/IV as string literal in createCipheriv
    if _HARDCODED_CRYPTO_KEY.search(raw):
        _add(
            "TS-020",
            Severity.HIGH,
            Confidence.HIGH,
            "Hardcoded cryptographic key or IV in createCipheriv/createDecipheriv — key material must not be in source",
            "Load keys from process.env or a secrets manager. Use crypto.randomBytes(32) for IV generation.",
        )

    # TS-021: CORS wildcard — Access-Control-Allow-Origin: * allows any origin
    if _CORS_WILDCARD.search(raw):
        _add(
            "TS-021",
            Severity.MEDIUM,
            Confidence.HIGH,
            "CORS wildcard origin (*) — any website can make cross-origin requests to this endpoint",
            "Restrict allowed origins to a known allowlist. Wildcard + credentials = auth bypass risk.",
        )

    # TS-022: SSTI — template engine rendered with user-supplied string
    if _SSTI_TEMPLATE.search(raw) and not _SSTI_LITERAL_SAFE.search(raw):
        _add(
            "TS-022",
            Severity.HIGH,
            Confidence.MEDIUM,
            "Template engine called with a variable — server-side template injection (SSTI) risk",
            "Use a fixed template path/string. Never pass user-supplied content as the template itself.",
        )

    # TS-023: ReDoS — user-controlled pattern passed to new RegExp()
    if _REDOS_REGEXP.search(raw) and not _REDOS_LITERAL_SAFE.search(raw):
        _add(
            "TS-023",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "new RegExp(variable) — user-controlled regex pattern can cause catastrophic backtracking (ReDoS)",
            "Reject user-supplied patterns. If needed, validate complexity and enforce a timeout.",
        )

    # TS-024: sensitive variable name passed to console.log / logger
    if _LOG_CALL.search(raw) and _LOG_SENSITIVE_NAME.search(raw):
        _add(
            "TS-024",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "Sensitive value passed to a logger — credentials or tokens may appear in log files",
            "Redact or mask secrets before logging. Never log raw tokens, passwords, or keys.",
        )

    # TS-025: security header explicitly removed
    if _SEC_HEADER_REMOVE.search(raw):
        _add(
            "TS-025",
            Severity.MEDIUM,
            Confidence.HIGH,
            "Security header explicitly removed — browsers lose the corresponding protection",
            "Never remove security headers. Set them once via middleware; do not delete them per-route.",
        )

    # TS-026: mass assignment — Object.assign or spread of req.body into an entity
    if _MASS_ASSIGN.search(raw):
        _add(
            "TS-026",
            Severity.HIGH,
            Confidence.HIGH,
            "Mass assignment: req.body spread or assigned into an object — attacker can overwrite any field",
            "Explicitly pick permitted fields: const { name, email } = req.body. Use a validation schema.",
        )

    # TS-027: path.join / path.resolve with variable segment — path traversal risk
    if _PATH_JOIN_VAR.search(raw) and not _PATH_JOIN_LITERAL_SAFE.search(raw):
        _add(
            "TS-027",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "path.join/resolve with variable segment — '../' sequences can escape the intended directory",
            "Resolve the joined path and assert it starts with the allowed base dir. Reject paths with '..'.",
        )

    # TS-028: fixed PRNG seed
    if _FIXED_SEED.search(raw):
        _add(
            "TS-028",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "PRNG seeded with a fixed value — random output becomes fully predictable",
            "Use crypto.randomBytes() for security tokens. Never seed with a constant.",
        )

    # TS-029: password hashed with fast algorithm
    if _FAST_HASH_PASSWORD.search(raw):
        _add(
            "TS-029",
            Severity.HIGH,
            Confidence.HIGH,
            "Password hashed with a fast algorithm (SHA-256/512) — not suitable for password storage",
            "Use bcrypt, argon2, or scrypt for password hashing. Fast hashes are trivially brute-forced.",
        )

    # TS-030: assert used for access control
    if _ASSERT_AUTH.search(raw):
        _add(
            "TS-030",
            Severity.HIGH,
            Confidence.MEDIUM,
            "assert used for access control — assertions can be disabled in production builds",
            "Replace assert with an explicit if/throw. Use middleware guards, not assertions, for auth checks.",
        )

    # TS-031: sensitive value in localStorage/sessionStorage — XSS-accessible
    if _LOCAL_STORAGE_SENSITIVE.search(raw):
        _add(
            "TS-031",
            Severity.MEDIUM,
            Confidence.HIGH,
            "Sensitive value stored in localStorage/sessionStorage — readable by any JS on the page",
            "Store tokens in memory or httpOnly cookies. Never put secrets in Web Storage.",
        )

    # TS-032: hardcoded JWT secret
    if _JWT_HARDCODED_SECRET.search(raw):
        _add(
            "TS-032",
            Severity.HIGH,
            Confidence.HIGH,
            "Hardcoded JWT secret in jwt.sign/verify — key material must not be in source code",
            "Load the JWT secret from process.env.JWT_SECRET. Never hardcode cryptographic secrets.",
        )

    # TS-033: DOM XSS via innerHTML / document.write with variable
    if _INNER_HTML_ASSIGN.search(raw) and not _INNER_HTML_LITERAL_SAFE.search(raw):
        _add(
            "TS-033",
            Severity.HIGH,
            Confidence.HIGH,
            "innerHTML/outerHTML/document.write with variable input — DOM-based XSS risk",
            "Use element.textContent instead of innerHTML. If HTML is needed, sanitise with DOMPurify.",
        )

    # TS-037: user-controlled executable in spawn / execFile — command injection
    if _SPAWN_VAR.search(raw) and not _SPAWN_LITERAL_SAFE.search(raw):
        _add(
            "TS-037",
            Severity.HIGH,
            Confidence.MEDIUM,
            "spawn/execFile with variable executable — user-controlled command name allows OS injection",
            "Validate the executable against an allowlist. Never let callers control the binary path.",
        )

    # TS-038: world-writable file permissions
    if _CHMOD_WORLD_WRITE.search(raw):
        _add(
            "TS-038",
            Severity.MEDIUM,
            Confidence.HIGH,
            "fs.chmod with world-writable permissions — any user on the system can modify the file",
            "Use restrictive permissions (e.g. 0o640 for files, 0o750 for dirs). Never grant o+w.",
        )

    # TS-039: base64 used as encryption/obfuscation on a security-sensitive value
    if _BASE64_SENSITIVE.search(raw):
        _add(
            "TS-039",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "base64 applied to a secret value — encoding is not encryption; value is trivially reversible",
            "Use a proper encryption library (node:crypto, libsodium) or a secrets manager instead.",
        )

    # TS-034: unsafe YAML deserialization — js-yaml .load() without schema
    if _YAML_LOAD_UNSAFE.search(raw) and not _YAML_LOAD_SAFE.search(raw):
        _add(
            "TS-034",
            Severity.MEDIUM,
            Confidence.HIGH,
            "yaml.load() without schema can execute arbitrary JS — unsafe YAML deserialisation",
            "Use yaml.safeLoad() or pass { schema: yaml.CORE_SCHEMA } to disable dangerous types.",
        )

    # TS-035: hardcoded fallback for sensitive environment variable
    m035 = _ENV_SENSITIVE_FALLBACK.search(raw)
    if m035 and _ENV_SENSITIVE_VARNAME.search(m035.group(1)):
        _add(
            "TS-035",
            Severity.MEDIUM,
            Confidence.HIGH,
            f"process.env.{m035.group(1)} with hardcoded fallback — secret leaks into source code",
            "Remove the fallback or use an empty string. Load secrets exclusively from the environment.",
        )

    # TS-036: open redirect using request query/body/params directly
    if _REDIRECT_FROM_REQ.search(raw):
        _add(
            "TS-036",
            Severity.MEDIUM,
            Confidence.HIGH,
            "Open redirect: URL taken directly from req.query/body/params — attacker can redirect to any site",
            "Validate the URL against an allowlist or use a safe relative path. Never trust raw request data.",
        )

    # TS-043: SQL injection via string concatenation in query/execute
    if _SQL_CONCAT_TS.search(raw):
        _add(
            "TS-043",
            Severity.HIGH,
            Confidence.HIGH,
            "SQL query built with string concatenation — SQL injection risk",
            "Use parameterised queries: db.query(sql, [params]). Never concatenate user values into SQL.",
        )

    # TS-044: HTTP header injection — user-controlled value from request written to response header
    if _HEADER_INJECT_TS.search(raw):
        _add(
            "TS-044",
            Severity.MEDIUM,
            Confidence.HIGH,
            "res.setHeader/append with request data — untrusted value allows CRLF/header injection",
            "Strip CR/LF characters from header values. Never write raw request data to response headers.",
        )

    # TS-045: file serving with user-controlled path — path traversal to arbitrary file read
    if _SEND_FILE_FROM_REQ.search(raw):
        _add(
            "TS-045",
            Severity.HIGH,
            Confidence.HIGH,
            "res.sendFile/download with request data — user-controlled path allows reading any file",
            "Validate the path against an allowlist or serve from a fixed directory using path.basename().",
        )

    # TS-055: crypto.randomBytes with user-controlled size — DoS via allocation
    if _RANDOM_BYTES_REQ.search(raw):
        _add(
            "TS-055",
            Severity.MEDIUM,
            Confidence.HIGH,
            "crypto.randomBytes(req.xxx) — user-controlled size enables denial of service via large allocation",
            "Cap the size to a sane maximum (e.g. ≤ 64) before passing to randomBytes().",
        )

    # TS-056: res.download() with request data — path traversal
    if _DOWNLOAD_FROM_REQ.search(raw):
        _add(
            "TS-056",
            Severity.HIGH,
            Confidence.HIGH,
            "res.download(req.xxx) — user-controlled path allows downloading arbitrary server files",
            "Resolve the path against a fixed base directory and validate it stays within that directory.",
        )

    # TS-057: exec(req.query.cmd) — direct exec with request variable (command injection)
    if _EXEC_VAR_REQ.search(raw):
        _add(
            "TS-057",
            Severity.CRITICAL,
            Confidence.HIGH,
            "exec(req.xxx) — user-controlled command string executes arbitrary shell commands",
            "Use execFile() with an args array and shell: false. Never pass request data to exec().",
        )

    # TS-058: execFile(req.xxx) — user-controlled executable file path
    if _EXEC_FILE_REQ.search(raw):
        _add(
            "TS-058",
            Severity.HIGH,
            Confidence.HIGH,
            "execFile(req.xxx) — user-controlled executable path allows arbitrary file execution",
            "Allowlist permitted executable paths. Never let callers supply the binary to run.",
        )

    # TS-059: net.createConnection with request data — raw TCP SSRF
    if _NET_CONNECT_REQ.search(raw):
        _add(
            "TS-059",
            Severity.MEDIUM,
            Confidence.HIGH,
            "net.createConnection(req.xxx) — user-controlled host/port enables raw TCP SSRF",
            "Hardcode the target host and port. Never allow callers to choose the TCP endpoint.",
        )

    # TS-060: res.jsonp(req.xxx) — JSONP callback injection
    if _JSONP_REQ.search(raw):
        _add(
            "TS-060",
            Severity.MEDIUM,
            Confidence.HIGH,
            "res.jsonp(req.xxx) — user-controlled JSONP data enables XSS via callback injection",
            "Sanitize and validate data before passing to res.jsonp(). Never use raw request data as JSONP payload.",
        )

    # TS-052: document.getElementById(req.xxx) — DOM injection via user-controlled element ID
    if _DOM_ID_INJECT.search(raw):
        _add(
            "TS-052",
            Severity.MEDIUM,
            Confidence.HIGH,
            "document.getElementById(req.xxx) — user-controlled ID can target unexpected DOM elements",
            "Validate or allowlist element IDs. Never use request data to select DOM nodes.",
        )

    # TS-053: fetch/axios with template literal URL built from request data — SSRF
    if _FETCH_TEMPLATE_REQ.search(raw):
        _add(
            "TS-053",
            Severity.HIGH,
            Confidence.HIGH,
            "fetch/axios URL built from request data — user-controlled path enables SSRF or path confusion",
            "Validate the URL path against an allowlist. Never interpolate request data directly into URLs.",
        )

    # TS-054: localStorage.getItem("token") used as a trusted auth source — insecure
    if _LOCAL_STORAGE_TRUST.search(raw):
        _add(
            "TS-054",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "localStorage.getItem('token') used as a security-sensitive value — localStorage is not secure storage",
            "Use httpOnly cookies for auth tokens. localStorage is readable by any JS on the page (XSS risk).",
        )

    # TS-049: setTimeout/setInterval with a variable callback — potential code injection
    if _SET_TIMEOUT_VAR.search(raw) and not _SET_TIMEOUT_LITERAL_SAFE.search(raw):
        _add(
            "TS-049",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "setTimeout/setInterval with a variable callback — user-controlled callable may execute arbitrary code",
            "Use a fixed, allowlisted callback function. Never pass user-controlled values as timer callbacks.",
        )

    # TS-050: process.exit() with user-controlled argument — denial of service
    if _PROCESS_EXIT_FROM_REQ.search(raw):
        _add(
            "TS-050",
            Severity.HIGH,
            Confidence.HIGH,
            "process.exit(req.xxx) — user-controlled exit code allows denial of service",
            "Never call process.exit() with user-supplied values. Handle errors with exceptions.",
        )

    # TS-051: DOM open redirect — window.location set from request parameter
    if _DOM_REDIRECT.search(raw):
        _add(
            "TS-051",
            Severity.MEDIUM,
            Confidence.HIGH,
            "window.location = req.xxx — DOM-based open redirect to user-controlled URL",
            "Validate the target URL against an allowlist of permitted origins before redirecting.",
        )

    # TS-046: fs.writeFile with user-controlled path from request — write to arbitrary path
    if _WRITE_FILE_FROM_REQ.search(raw):
        _add(
            "TS-046",
            Severity.HIGH,
            Confidence.HIGH,
            "fs.writeFile path from request — user-controlled destination allows overwriting arbitrary files",
            "Resolve the path against a fixed base directory and validate it stays within that directory.",
        )

    # TS-047: require(variable) — dynamic module loading with non-literal argument
    if _REQUIRE_VAR.search(raw) and not _REQUIRE_LITERAL_SAFE.search(raw):
        _add(
            "TS-047",
            Severity.HIGH,
            Confidence.MEDIUM,
            "require(variable) — dynamic module loading with a non-literal path enables module injection",
            "Allowlist permitted module names and use a static require() or import statement.",
        )

    # TS-048: child_process.fork() with user-controlled script path
    if _FORK_FROM_REQ.search(raw):
        _add(
            "TS-048",
            Severity.CRITICAL,
            Confidence.HIGH,
            "fork() script path from request — user-controlled script executes arbitrary Node.js code",
            "Never use request data as the fork() script argument. Use a fixed, allowlisted script path.",
        )

    # TS-040: new Function() with dynamic argument — runtime code compilation (like eval for statements)
    if _NEW_FUNCTION_VAR.search(raw) and not _NEW_FUNCTION_LITERAL_SAFE.search(raw):
        _add(
            "TS-040",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new Function(variable) constructs and executes code at runtime — equivalent to eval() for statements",
            "Remove new Function(). Use explicit logic, a safe expression parser, or a sandboxed worker.",
        )

    # TS-041: credentials embedded in connection-string URL
    if _CRED_URL_TS.search(raw):
        _add(
            "TS-041",
            Severity.CRITICAL,
            Confidence.HIGH,
            "Credentials embedded in connection-string URL — password visible in source, logs and version history",
            "Use environment variables for user/password and build the URL at runtime. Never commit credentials.",
        )

    # TS-042: vm.runInNewContext / vm.Script with dynamic code — vm is not a security sandbox
    if _VM_RUN_VAR.search(raw) and not _VM_RUN_LITERAL_SAFE.search(raw):
        _add(
            "TS-042",
            Severity.HIGH,
            Confidence.HIGH,
            "vm.runInNewContext/Script with dynamic code — Node.js vm is not a security sandbox; breakout is easy",
            "Do not use vm for untrusted code isolation. Use a worker_threads sandbox or a separate process.",
        )

    return result
