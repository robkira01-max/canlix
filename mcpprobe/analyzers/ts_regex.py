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
# TS-061: fs.readFileSync(req.xxx) — synchronous path traversal
# ---------------------------------------------------------------------------

_READ_FILE_SYNC_REQ = re.compile(
    r"""(?x)
    \bfs\.readFileSync\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-062: child_process.spawnSync(req.xxx) — synchronous shell execution
# ---------------------------------------------------------------------------

_SPAWN_SYNC_REQ = re.compile(
    r"""(?x)
    \b(?:child_process\.spawnSync|(?<![A-Za-z0-9_$])spawnSync)\s*\(
    \s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-063: new vm.Script(req.xxx) — user-controlled code compiled into VM script
# ---------------------------------------------------------------------------

_VM_SCRIPT_REQ = re.compile(
    r"""(?x)
    \bnew\s+(?:vm\.)?Script\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-064: document.write(req.xxx) — DOM XSS via document.write
# ---------------------------------------------------------------------------

_DOC_WRITE_REQ = re.compile(
    r"""(?x)
    \bdocument\.write(?:ln)?\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-065: window.open(req.xxx) — DOM open redirect via window.open
# ---------------------------------------------------------------------------

_WINDOW_OPEN_REQ = re.compile(
    r"""(?x)
    \bwindow\.open\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-066: $(el).html(req.xxx) — jQuery innerHTML injection
# ---------------------------------------------------------------------------

_JQUERY_HTML_REQ = re.compile(
    r"""(?x)
    \)\.html\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-067: Object.defineProperty(obj, req.xxx, ...) — user-controlled property name
# ---------------------------------------------------------------------------

_OBJ_DEFINE_PROP_REQ = re.compile(
    r"""(?x)
    \bObject\.defineProperty\s*\([^,]+,\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-068: crypto.createCipheriv / createDecipheriv with user-controlled algo
# ---------------------------------------------------------------------------

_CRYPTO_CIPHER_ALGO_REQ = re.compile(
    r"""(?x)
    \bcrypto\.create(?:Cipher|Decipher)iv\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-069: fs.writeFileSync(req.xxx, ...) — synchronous write path traversal
# ---------------------------------------------------------------------------

_WRITE_FILE_SYNC_REQ = re.compile(
    r"""(?x)
    \bfs\.writeFileSync\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-070: res.set(req.xxx, ...) — user-controlled response header name injection
# ---------------------------------------------------------------------------

_RES_SET_HEADER_REQ = re.compile(
    r"""(?x)
    \bres\.(?:set|header)\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-071: new Worker(req.xxx) — user-controlled Web Worker script URL
# ---------------------------------------------------------------------------

_NEW_WORKER_REQ = re.compile(
    r"""(?x)
    \bnew\s+Worker\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-072: XMLHttpRequest.open("METHOD", req.xxx) — SSRF via XHR
# ---------------------------------------------------------------------------

_XHR_OPEN_REQ = re.compile(
    r"""(?x)
    \.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH|HEAD)["']\s*,\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-073: res.render(req.xxx, ...) — user-controlled template name, SSTI / path traversal
_RES_RENDER_REQ = re.compile(
    r"""(?x)
    \bres\.render\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-074: fs.appendFile(req.xxx, ...) — user-controlled append path
_APPEND_FILE_REQ = re.compile(
    r"""(?x)
    \bfs\.appendFile(?:Sync)?\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-075: crypto.pbkdf2(req.xxx, ...) — user-controlled input in async KDF, DoS
_PBKDF2_REQ = re.compile(
    r"""(?x)
    \bcrypto\.pbkdf2\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-076: NoSQL injection — .find(req.xxx) passes user object to MongoDB query
_NOSQL_FIND_REQ = re.compile(
    r"""(?x)
    \.find\s*\(\s*
    req\.(?:query|params|body)(?:\.[A-Za-z_$][A-Za-z0-9_$.]*)?
    \s*[,)]
    """,
)

# TS-077: spawn/spawnSync with template literal containing req.xxx as program name
_SPAWN_TMPL_REQ = re.compile(
    r"""(?x)
    \b(?:child_process\.)?spawn(?:Sync)?\s*\(\s*`[^`]*
    \$\{req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*\}
    """,
)

# TS-078: res.cookie(name, req.xxx) — user-controlled cookie value
_COOKIE_VALUE_REQ = re.compile(
    r"""(?x)
    \bres\.cookie\s*\([^,]+,\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-079: fs.createReadStream(req.xxx) — user-controlled stream read path
_CREATE_READ_STREAM_REQ = re.compile(
    r"""(?x)
    \bfs\.createReadStream\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-080: exec("..." + req.xxx) — string concatenation in exec call
_EXEC_CONCAT_REQ = re.compile(
    r"""(?x)
    \b(?:child_process\.exec|(?<![A-Za-z0-9_$])exec)\s*\(
    [^)]*\+\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-081: mongoose.connect(req.xxx) / new MongoClient(req.xxx) — user-controlled DB URI
_MONGO_CONNECT_REQ = re.compile(
    r"""(?x)
    (?:\bmongoose\.connect|new\s+MongoClient)\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-082: fs.chmod(req.xxx, ...) — user-controlled path in permission change
_CHMOD_PATH_REQ = re.compile(
    r"""(?x)
    \bfs\.chmod(?:Sync)?\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-083: res.type(req.xxx) — user-controlled Content-Type header, MIME/CRLF injection
_RES_TYPE_REQ = re.compile(
    r"""(?x)
    \bres\.type\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-084: import(req.xxx) — dynamic import with user-controlled specifier
_DYNAMIC_IMPORT_REQ = re.compile(
    r"""(?x)
    \bimport\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-085: req.session[req.xxx] — user-controlled session key access
_SESSION_KEY_REQ = re.compile(
    r"""(?x)
    \breq\.session\s*\[\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-086: Sequelize.query(req.xxx) / sequelize.query(req.xxx) — raw ORM query injection
_SEQUELIZE_QUERY_REQ = re.compile(
    r"""(?x)
    \bsequelize(?:Instance)?\.query\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    |
    \b(?:db|pool|connection)\.query\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
    re.IGNORECASE,
)

# TS-087: res.locals[req.xxx] — user-controlled res.locals key
_RES_LOCALS_KEY_REQ = re.compile(
    r"""(?x)
    \bres\.locals\s*\[\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-088: fs.mkdir / fs.mkdirSync with user-controlled path — arbitrary directory creation
_FS_MKDIR_REQ = re.compile(
    r"""(?x)
    \bfs\.mkdirs?(?:Sync)?\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-089: execFileSync with user-controlled executable — synchronous command injection
_EXECFILESYNC_REQ = re.compile(
    r"""(?x)
    \bexecFileSync\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-090: process.env[req.xxx] — user-controlled env variable key read (potential secret leak)
_PROCESS_ENV_KEY_REQ = re.compile(
    r"""(?x)
    \bprocess\.env\s*\[\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-091: axios.get/post/put/delete(req.xxx) — SSRF via axios with user-controlled URL
_AXIOS_REQ = re.compile(
    r"""(?x)
    \baxios\.(?:get|post|put|delete|patch|request|head)\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-092: res.send(req.xxx) — XSS via unsanitized response body
_RES_SEND_REQ = re.compile(
    r"""(?x)
    \bres\.send\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-093: JSON.parse(req.xxx) — prototype pollution / DoS via unchecked JSON
_JSON_PARSE_REQ = re.compile(
    r"""(?x)
    \bJSON\.parse\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-094: fs.symlink(req.xxx, ...) — user-controlled symlink target (symlink attack)
_FS_SYMLINK_REQ = re.compile(
    r"""(?x)
    \bfs\.symlinks?\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-095: mongoose.model(req.xxx) — user-controlled model name, accesses arbitrary collection
_MONGOOSE_MODEL_REQ = re.compile(
    r"""(?x)
    \bmongoose\.model\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-096: Buffer.allocUnsafe(req.xxx) — user-controlled buffer size, DoS risk
_BUFFER_ALLOC_REQ = re.compile(
    r"""(?x)
    \bBuffer\.allocUnsafe\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-097: Handlebars.compile(req.xxx) — SSTI via user-controlled Handlebars template
_HANDLEBARS_COMPILE_REQ = re.compile(
    r"""(?x)
    \bHandlebars\.compile\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-098: fs.unlink/unlinkSync(req.xxx) — user-controlled file deletion
_FS_UNLINK_REQ = re.compile(
    r"""(?x)
    \bfs\.unlink(?:Sync)?\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-099: http.get/request(req.xxx) — SSRF via Node.js stdlib http module
_HTTP_MODULE_REQ = re.compile(
    r"""(?x)
    \bhttp(?:s)?\.(?:get|request)\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-100: res.attachment(req.xxx) — user-controlled Content-Disposition filename (header injection)
_RES_ATTACHMENT_REQ = re.compile(
    r"""(?x)
    \bres\.attachment\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-101: socket.emit(req.xxx) — user-controlled Socket.IO event name injection
_SOCKET_EMIT_REQ = re.compile(
    r"""(?x)
    \bsocket\.emit\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-102: $.ajax({url: req.xxx}) — jQuery SSRF via user-controlled URL
_JQUERY_AJAX_URL_REQ = re.compile(
    r"""(?x)
    \$\.ajax\s*\(\s*\{[^}]*\burl\s*:\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-103: redis.createClient({url: req.xxx}) — SSRF via user-controlled Redis URL
_REDIS_CREATE_CLIENT_REQ = re.compile(
    r"""(?x)
    \bcreateClient\s*\(\s*\{[^}]*\burl\s*:\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-104: amqplib.connect(req.xxx) — SSRF via user-controlled RabbitMQ URL
_AMQPLIB_CONNECT_REQ = re.compile(
    r"""(?x)
    \bamqplib(?:\.node)?\s*\.\s*connect\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-105: pg.connect(req.xxx) / new pg.Client(...) — SSRF via PostgreSQL connection string
_PG_CONNECT_REQ = re.compile(
    r"""(?x)
    \bpg\.connect\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-106: new WebSocket(req.xxx) — SSRF via user-controlled WebSocket URL
_WEBSOCKET_REQ = re.compile(
    r"""(?x)
    \bnew\s+WebSocket\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-107: new EventSource(req.xxx) — SSRF via user-controlled EventSource URL
_EVENT_SOURCE_REQ = re.compile(
    r"""(?x)
    \bnew\s+EventSource\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-108: new Client({node: req.xxx}) / elasticsearch — SSRF via user-controlled node URL
_ES_CLIENT_NODE_REQ = re.compile(
    r"""(?x)
    \bnew\s+(?:elasticsearch\.)?Client\s*\(\s*\{[^}]*\bnode\s*:\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-109: res.cookie(req.xxx, ...) — user-controlled cookie name (header injection)
_COOKIE_NAME_REQ = re.compile(
    r"""(?x)
    \bres\.cookie\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    \s*,
    """,
)

# TS-110: crypto.scrypt(req.xxx, ...) — DoS via user-controlled password in scrypt
_CRYPTO_SCRYPT_REQ = re.compile(
    r"""(?x)
    \bcrypto\.scrypt\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-111: new URL(req.xxx) — SSRF / open redirect via user-controlled URL constructor
_NEW_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+URL\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-112: mysql.createConnection({host: req.xxx}) / mysql2.createConnection({host:req.xxx}) — SSRF
_MYSQL_CONN_REQ = re.compile(
    r"""(?x)
    \b(?:mysql2?\.create(?:Connection|Pool))\s*\(\s*\{[^}]*\bhost\s*:\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-113: new Redis(req.xxx) (ioredis) — user-controlled Redis connection string
_IOREDIS_NEW_REQ = re.compile(
    r"""(?x)
    \bnew\s+Redis\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-114: createConnection({host: req.xxx}) (TypeORM) — SSRF via user-controlled host
_TYPEORM_CONN_REQ = re.compile(
    r"""(?x)
    \bcreateConnection\s*\(\s*\{[^}]*\bhost\s*:\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-115: undici.request(req.xxx) / undici.fetch(req.xxx) — SSRF via undici HTTP client
_UNDICI_REQ = re.compile(
    r"""(?x)
    \bundici\.(?:request|fetch|stream)\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-116: superagent.get/post(req.xxx) — SSRF via superagent with user-controlled URL
_SUPERAGENT_REQ = re.compile(
    r"""(?x)
    \bsuperagent\.(?:get|post|put|delete|patch|request)\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-117: ky.get/post(req.xxx) / ky(req.xxx) — SSRF via ky HTTP client
_KY_REQ = re.compile(
    r"""(?x)
    \bky(?:\.(?:get|post|put|delete|patch))?\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-118: element.setAttribute("src"|"href", req.xxx) — DOM attribute injection XSS / open redirect
_SET_ATTR_SRC_HREF_REQ = re.compile(
    r"""(?x)
    \.setAttribute\s*\(\s*["'](?:src|href|action|data|formaction)["']\s*,\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-119: location.assign(req.xxx) / location.replace(req.xxx) — open redirect via location
_LOCATION_ASSIGN_REQ = re.compile(
    r"""(?x)
    \blocation\.(?:assign|replace)\s*\(\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# TS-120: new S3Client({endpoint: req.xxx}) / new DynamoDBClient({endpoint: req.xxx}) — AWS SSRF
_AWS_SDK_ENDPOINT_REQ = re.compile(
    r"""(?x)
    \bnew\s+(?:S3|DynamoDB|Lambda|SQS|SNS|SES|EC2|ECS|IAM|KMS|SecretsManager)Client\s*\(\s*\{[^}]*\bendpoint\s*:\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-121: new Kafka({ brokers: req.xxx }) — SSRF via user-controlled KafkaJS brokers
# ---------------------------------------------------------------------------

_KAFKAJS_BROKERS_REQ = re.compile(
    r"""(?x)
    \bnew\s+Kafka\s*\(\s*\{[^}]*\bbrokers\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-122: tls.connect({ host: req.xxx }) — SSRF via user-controlled TLS host
# ---------------------------------------------------------------------------

_TLS_CONNECT_REQ = re.compile(
    r"""(?x)
    \btls\.connect\s*\(\s*\{[^}]*\bhost\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-123: nats.connect(req.xxx) — SSRF via user-controlled NATS server URL
# ---------------------------------------------------------------------------

_NATS_CONNECT_REQ = re.compile(
    r"""(?x)
    \bnats\.connect\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-124: new InfluxDB({ url: req.xxx }) — SSRF via user-controlled InfluxDB URL
# ---------------------------------------------------------------------------

_INFLUXDB_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+InfluxDB\s*\(\s*\{[^}]*\burl\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-125: neo4j.driver(req.xxx) — SSRF via user-controlled Neo4j URI
# ---------------------------------------------------------------------------

_NEO4J_DRIVER_REQ = re.compile(
    r"""(?x)
    \bneo4j\.driver\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-126: new ClickHouse({ host: req.xxx }) — SSRF via user-controlled ClickHouse host
# ---------------------------------------------------------------------------

_CLICKHOUSE_HOST_REQ = re.compile(
    r"""(?x)
    \bnew\s+ClickHouse\s*\(\s*\{[^}]*\bhost\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-127: weaviateClient.connectToCustom({ httpHost: req.xxx }) -- Weaviate SSRF
# ---------------------------------------------------------------------------

_WEAVIATE_HOST_REQ = re.compile(
    r"""(?x)
    \bnew\s+WeaviateClient\s*\(\s*\{[^}]*\bhttpHost\s*:\s*
    req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-128: new QdrantClient({ url: req.xxx }) -- Qdrant vector DB SSRF
# ---------------------------------------------------------------------------

_QDRANT_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+QdrantClient\s*\(\s*\{[^}]*\b(?:url|host)\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-129: new ChromaClient({ path: req.xxx }) -- ChromaDB SSRF
# ---------------------------------------------------------------------------

_CHROMA_PATH_REQ = re.compile(
    r"""(?x)
    \bnew\s+ChromaClient\s*\(\s*\{[^}]*\bpath\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-130: new OpenAI({ baseURL: req.xxx }) -- SSRF / API key exfiltration
# ---------------------------------------------------------------------------

_OPENAI_BASE_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+OpenAI\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-131: new Anthropic({ baseURL: req.xxx }) -- SSRF / API key exfiltration
# ---------------------------------------------------------------------------

_ANTHROPIC_BASE_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+Anthropic\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-132: new MilvusClient({ address: req.xxx }) -- Milvus vector DB SSRF
# ---------------------------------------------------------------------------

_MILVUS_ADDRESS_REQ = re.compile(
    r"""(?x)
    \bnew\s+MilvusClient\s*\(\s*\{[^}]*\baddress\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-133: new Groq({ baseURL: req.xxx }) -- SSRF / API key exfiltration
# ---------------------------------------------------------------------------

_GROQ_BASE_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+Groq\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-134: new CohereClient({ baseURL: req.xxx }) -- SSRF / API key exfiltration
# ---------------------------------------------------------------------------

_COHERE_BASE_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+CohereClient\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-135: new MistralClient({ serverURL: req.xxx }) -- SSRF / API key exfiltration
# ---------------------------------------------------------------------------

_MISTRAL_SERVER_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+Mistral(?:Client)?\s*\(\s*\{[^}]*\bserverURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-136: new Together({ baseURL: req.xxx }) -- Together AI SSRF / API key exfil
# ---------------------------------------------------------------------------

_TOGETHER_BASE_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+Together\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-137: new ReplicateClient({ baseURL: req.xxx }) -- Replicate SSRF / API key exfil
# ---------------------------------------------------------------------------

_REPLICATE_BASE_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+ReplicateClient\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-138: new HuggingFaceInference({ baseURL: req.xxx }) -- HF inference SSRF
# ---------------------------------------------------------------------------

_HF_INFERENCE_BASE_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+HuggingFaceInference\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-139: new VoyageAI({ baseURL: req.xxx }) -- Voyage AI SSRF / API key exfil
# ---------------------------------------------------------------------------

_VOYAGE_BASE_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+VoyageAI\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-140: new AzureOpenAI({ endpoint: req.xxx }) -- Azure AI SSRF / API key exfil
# ---------------------------------------------------------------------------

_AZURE_OPENAI_ENDPOINT_REQ = re.compile(
    r"""(?x)
    \bnew\s+AzureOpenAI\s*\(\s*\{[^}]*\bendpoint\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-141: new AI21({ baseURL: req.xxx }) -- AI21 Labs SSRF / API key exfil
# ---------------------------------------------------------------------------

_AI21_BASE_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+AI21\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-142: axios.create({ baseURL: req.xxx }) -- SSRF via axios instance base URL
# ---------------------------------------------------------------------------

_AXIOS_CREATE_BASE_URL_REQ = re.compile(
    r"""(?x)
    \baxios\.create\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-143: new Cerebras({ baseURL: req.xxx }) -- Cerebras AI SSRF / API key exfil
# ---------------------------------------------------------------------------

_CEREBRAS_BASE_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+Cerebras\s*\(\s*\{[^}]*\bbaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-144: new BlobServiceClient(req.xxx) -- Azure Blob SSRF via user-controlled URL
# ---------------------------------------------------------------------------

_BLOB_SERVICE_CLIENT_URL_REQ = re.compile(
    r"""(?x)
    \bnew\s+BlobServiceClient\s*\(\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-145: new Storage({ apiEndpoint: req.xxx }) -- Google Cloud Storage SSRF
# ---------------------------------------------------------------------------

_GCS_API_ENDPOINT_REQ = re.compile(
    r"""(?x)
    \bnew\s+Storage\s*\(\s*\{[^}]*\bapiEndpoint\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-146: initializeApp({ databaseURL: req.xxx }) -- Firebase SSRF
# ---------------------------------------------------------------------------

_FIREBASE_DATABASE_URL_REQ = re.compile(
    r"""(?x)
    \binitializeApp\s*\(\s*\{[^}]*\bdatabaseURL\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
    """,
)

# ---------------------------------------------------------------------------
# TS-147: new BigQuery({ apiEndpoint: req.xxx }) -- Google BigQuery SSRF
# ---------------------------------------------------------------------------

_BIGQUERY_API_ENDPOINT_REQ = re.compile(
    r"""(?x)
    \bnew\s+BigQuery\s*\(\s*\{[^}]*\bapiEndpoint\s*:\s*req\.(?:query|params|body)\.[A-Za-z_$][A-Za-z0-9_$.]*
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

    # TS-061: fs.readFileSync(req.xxx) — synchronous path traversal
    if _READ_FILE_SYNC_REQ.search(raw):
        _add(
            "TS-061",
            Severity.HIGH,
            Confidence.HIGH,
            "fs.readFileSync(req.xxx) — user-controlled path allows reading arbitrary server files",
            "Validate the path against an allowlist or use an async read with proper path sanitization.",
        )

    # TS-062: spawnSync(req.xxx) — synchronous shell execution with user-controlled command
    if _SPAWN_SYNC_REQ.search(raw):
        _add(
            "TS-062",
            Severity.HIGH,
            Confidence.HIGH,
            "spawnSync(req.xxx) — user-controlled executable in synchronous spawn allows OS command injection",
            "Allowlist permitted executables. Use spawnSync with a fixed binary and an args array.",
        )

    # TS-063: new vm.Script(req.xxx) — user-controlled code compiled into VM script
    if _VM_SCRIPT_REQ.search(raw):
        _add(
            "TS-063",
            Severity.HIGH,
            Confidence.HIGH,
            "new vm.Script(req.xxx) — user-controlled code compiled as a VM script; vm is NOT a sandbox",
            "Never compile user-supplied code. Use a safe DSL or allowlisted template engine instead.",
        )

    # TS-070: res.set(req.xxx, ...) — user-controlled response header name injection
    if _RES_SET_HEADER_REQ.search(raw):
        _add(
            "TS-070",
            Severity.MEDIUM,
            Confidence.HIGH,
            "res.set(req.xxx, ...) — user-controlled header name enables CRLF / response-splitting injection",
            "Allowlist permitted header names. Never write raw request data to response header names.",
        )

    # TS-071: new Worker(req.xxx) — user-controlled Web Worker script URL
    if _NEW_WORKER_REQ.search(raw):
        _add(
            "TS-071",
            Severity.HIGH,
            Confidence.HIGH,
            "new Worker(req.xxx) — user-controlled script URL loads arbitrary code as a Web Worker",
            "Hardcode the Worker script URL or validate it against an allowlist.",
        )

    # TS-072: xhr.open("METHOD", req.xxx) — SSRF via XHR
    if _XHR_OPEN_REQ.search(raw):
        _add(
            "TS-072",
            Severity.MEDIUM,
            Confidence.HIGH,
            "xhr.open(method, req.xxx) — user-controlled URL in XMLHttpRequest enables SSRF",
            "Validate the URL against an allowlist of permitted hosts before calling xhr.open().",
        )

    # TS-073: res.render(req.xxx, ...) — user-controlled template name
    if _RES_RENDER_REQ.search(raw):
        _add(
            "TS-073",
            Severity.MEDIUM,
            Confidence.HIGH,
            "res.render(req.xxx) — user-controlled template name enables path traversal and SSTI",
            "Allowlist valid template names. Never let request data determine which template to render.",
        )

    # TS-074: fs.appendFile(req.xxx, ...) — user-controlled path
    if _APPEND_FILE_REQ.search(raw):
        _add(
            "TS-074",
            Severity.HIGH,
            Confidence.HIGH,
            "fs.appendFile path from request — user-controlled path allows writing to arbitrary files",
            "Resolve the path against a fixed base directory and validate it stays within that directory.",
        )

    # TS-075: crypto.pbkdf2(req.xxx, ...) — user-controlled KDF input enables DoS
    if _PBKDF2_REQ.search(raw):
        _add(
            "TS-075",
            Severity.MEDIUM,
            Confidence.HIGH,
            "crypto.pbkdf2(req.xxx) — user-controlled input in async KDF enables CPU-exhaustion DoS",
            "Cap password length and enforce a fixed iteration count. Never let callers control KDF parameters.",
        )

    # TS-076: .find(req.xxx) — NoSQL injection, user object passed to MongoDB query
    if _NOSQL_FIND_REQ.search(raw):
        _add(
            "TS-076",
            Severity.HIGH,
            Confidence.HIGH,
            ".find(req.xxx) — user-controlled query object enables NoSQL operator injection",
            "Validate and sanitise query fields. Never pass raw request objects to database query methods.",
        )

    # TS-077: spawn(template-literal with req.xxx) — command injection via template literal
    if _SPAWN_TMPL_REQ.search(raw):
        _add(
            "TS-077",
            Severity.HIGH,
            Confidence.HIGH,
            "spawn(`...${req.xxx}`) — user-controlled template literal in spawn enables command injection",
            "Build the command argument list from allowlisted values. Never interpolate request data into spawn().",
        )

    # TS-078: res.cookie(name, req.xxx) — user-controlled cookie value
    if _COOKIE_VALUE_REQ.search(raw):
        _add(
            "TS-078",
            Severity.MEDIUM,
            Confidence.HIGH,
            "res.cookie(name, req.xxx) — user-controlled cookie value enables session fixation and header injection",
            "Validate and sanitise the cookie value. Never set cookies directly from request data.",
        )

    # TS-079: fs.createReadStream(req.xxx) — user-controlled stream read path
    if _CREATE_READ_STREAM_REQ.search(raw):
        _add(
            "TS-079",
            Severity.MEDIUM,
            Confidence.HIGH,
            "fs.createReadStream path from request — user-controlled path enables read path traversal",
            "Resolve the path against a fixed base directory and validate it stays within that directory.",
        )

    # TS-080: exec("..." + req.xxx) — string concatenation in exec call
    if _EXEC_CONCAT_REQ.search(raw):
        _add(
            "TS-080",
            Severity.HIGH,
            Confidence.HIGH,
            'exec("..." + req.xxx) — string concatenation in exec enables command injection',
            "Remove exec(). Use child_process.spawn with a fixed command and an allowlisted argument list.",
        )

    # TS-081: mongoose.connect(req.xxx) / new MongoClient(req.xxx) — user-controlled DB URI
    if _MONGO_CONNECT_REQ.search(raw):
        _add(
            "TS-081",
            Severity.MEDIUM,
            Confidence.HIGH,
            "mongoose.connect/MongoClient(req.xxx) — user-controlled DB URI enables SSRF and credential theft",
            "Hardcode the DB URI in environment variables. Never let request data determine the database host.",
        )

    # TS-082: fs.chmod(req.xxx, ...) — user-controlled path in permission change
    if _CHMOD_PATH_REQ.search(raw):
        _add(
            "TS-082",
            Severity.MEDIUM,
            Confidence.HIGH,
            "fs.chmod path from request — attacker chooses which file to change permissions on",
            "Resolve the path against a fixed base directory and validate it stays within that directory.",
        )

    # TS-083: res.type(req.xxx) — user-controlled Content-Type header
    if _RES_TYPE_REQ.search(raw):
        _add(
            "TS-083",
            Severity.MEDIUM,
            Confidence.HIGH,
            "res.type(req.xxx) — user-controlled Content-Type header enables MIME sniffing and CRLF injection",
            "Allowlist valid MIME types. Never set the Content-Type from request data.",
        )

    # TS-084: import(req.xxx) — dynamic import with user-controlled specifier
    if _DYNAMIC_IMPORT_REQ.search(raw):
        _add(
            "TS-084",
            Severity.HIGH,
            Confidence.HIGH,
            "import(req.xxx) — user-controlled dynamic import loads arbitrary modules",
            "Allowlist module specifiers. Never let request data determine which module to import.",
        )

    # TS-085: req.session[req.xxx] — user-controlled session key access
    if _SESSION_KEY_REQ.search(raw):
        _add(
            "TS-085",
            Severity.MEDIUM,
            Confidence.HIGH,
            "req.session[req.xxx] — user-controlled session key enables session data theft or injection",
            "Use a fixed set of session keys. Never let request data determine which session property to access.",
        )

    # TS-086: sequelize.query(req.xxx) — raw ORM query injection
    if _SEQUELIZE_QUERY_REQ.search(raw):
        _add(
            "TS-086",
            Severity.HIGH,
            Confidence.HIGH,
            "sequelize.query/db.query(req.xxx) — user-controlled raw query string enables SQL injection",
            "Use parameterised queries or the ORM's model API. Never pass request data directly to query().",
        )

    # TS-087: res.locals[req.xxx] — user-controlled res.locals key
    if _RES_LOCALS_KEY_REQ.search(raw):
        _add(
            "TS-087",
            Severity.MEDIUM,
            Confidence.HIGH,
            "res.locals[req.xxx] — user-controlled property key on res.locals enables prototype pollution",
            "Use a fixed set of res.locals keys. Never let request data determine which property to set.",
        )

    # TS-088: fs.mkdir/mkdirSync(req.xxx) — user-controlled directory creation path
    if _FS_MKDIR_REQ.search(raw):
        _add(
            "TS-088",
            Severity.MEDIUM,
            Confidence.HIGH,
            "fs.mkdir(req.xxx) — user-controlled path enables arbitrary directory creation",
            "Validate and sanitize directory paths. Never pass request data directly to fs.mkdir.",
        )

    # TS-089: execFileSync(req.xxx) — synchronous execution with user-controlled binary
    if _EXECFILESYNC_REQ.search(raw):
        _add(
            "TS-089",
            Severity.HIGH,
            Confidence.HIGH,
            "execFileSync(req.xxx) — user-controlled executable path enables OS command injection",
            "Hardcode the executable path. Never allow callers to supply the binary to execFileSync.",
        )

    # TS-090: process.env[req.xxx] — user-controlled env key read, may expose secrets
    if _PROCESS_ENV_KEY_REQ.search(raw):
        _add(
            "TS-090",
            Severity.MEDIUM,
            Confidence.HIGH,
            "process.env[req.xxx] — user-controlled key can read arbitrary environment variables including secrets",
            "Use a fixed allowlist of env variable names. Never let request data choose which env var to read.",
        )

    # TS-091: axios.get/post(req.xxx) — SSRF via axios with user-controlled URL
    if _AXIOS_REQ.search(raw):
        _add(
            "TS-091",
            Severity.HIGH,
            Confidence.HIGH,
            "axios.*(req.xxx) — user-controlled URL passed to axios enables SSRF",
            "Validate and allowlist target URLs. Never pass raw request data to axios as the target URL.",
        )

    # TS-092: res.send(req.xxx) — unsanitized value in response body, XSS risk
    if _RES_SEND_REQ.search(raw):
        _add(
            "TS-092",
            Severity.MEDIUM,
            Confidence.HIGH,
            "res.send(req.xxx) — user-controlled value sent as response body; XSS if HTML content-type",
            "Sanitize or encode user data before including it in a response body.",
        )

    # TS-093: JSON.parse(req.xxx) — prototype pollution / DoS via unchecked JSON payload
    if _JSON_PARSE_REQ.search(raw):
        _add(
            "TS-093",
            Severity.MEDIUM,
            Confidence.HIGH,
            "JSON.parse(req.xxx) — user-controlled JSON; risk of prototype pollution or DoS via deeply nested input",
            "Validate JSON structure and depth after parsing. Use a safe-merge or schema validator.",
        )

    # TS-094: fs.symlink(req.xxx) — user-controlled symlink target (symlink attack)
    if _FS_SYMLINK_REQ.search(raw):
        _add(
            "TS-094",
            Severity.HIGH,
            Confidence.HIGH,
            "fs.symlink(req.xxx, ...) — user-controlled symlink target enables symlink attack on arbitrary paths",
            "Validate the target path. Never allow callers to control the symlink destination.",
        )

    # TS-095: mongoose.model(req.xxx) — user-controlled model name, arbitrary collection access
    if _MONGOOSE_MODEL_REQ.search(raw):
        _add(
            "TS-095",
            Severity.HIGH,
            Confidence.HIGH,
            "mongoose.model(req.xxx) — user-controlled model name enables access to arbitrary DB collections",
            "Allowlist model names. Never let request data determine which Mongoose model to load.",
        )

    # TS-096: Buffer.allocUnsafe(req.xxx) — user-controlled size enables DoS via large allocation
    if _BUFFER_ALLOC_REQ.search(raw):
        _add(
            "TS-096",
            Severity.MEDIUM,
            Confidence.HIGH,
            "Buffer.allocUnsafe(req.xxx) — user-controlled buffer size can cause out-of-memory DoS",
            "Cap allocation size to a sane maximum. Never pass raw request data to Buffer.allocUnsafe.",
        )

    # TS-097: Handlebars.compile(req.xxx) — SSTI via user-controlled template
    if _HANDLEBARS_COMPILE_REQ.search(raw):
        _add(
            "TS-097",
            Severity.HIGH,
            Confidence.HIGH,
            "Handlebars.compile(req.xxx) — user-controlled template enables server-side template injection",
            "Pre-compile templates at startup from trusted sources. Never compile user-supplied strings.",
        )

    # TS-098: fs.unlink/unlinkSync(req.xxx) — user-controlled path allows arbitrary file deletion
    if _FS_UNLINK_REQ.search(raw):
        _add(
            "TS-098",
            Severity.HIGH,
            Confidence.HIGH,
            "fs.unlink(req.xxx) — user-controlled path allows arbitrary file deletion",
            "Resolve path against a fixed base directory and validate it stays within that directory.",
        )

    # TS-099: http.get/request(req.xxx) — SSRF via Node.js stdlib http module
    if _HTTP_MODULE_REQ.search(raw):
        _add(
            "TS-099",
            Severity.HIGH,
            Confidence.HIGH,
            "http.get/request(req.xxx) — user-controlled URL enables SSRF via Node.js http module",
            "Hardcode the target host. Never pass request data as the URL to http.get() or http.request().",
        )

    # TS-067: Object.defineProperty(obj, req.xxx, ...) — property name injection

    # TS-100: res.attachment(req.xxx) — user-controlled filename in Content-Disposition header
    if _RES_ATTACHMENT_REQ.search(raw):
        _add(
            "TS-100",
            Severity.MEDIUM,
            Confidence.HIGH,
            "res.attachment(req.xxx) — user-controlled filename may enable header injection or path traversal",
            "Sanitize the filename: strip path separators and disallow special characters.",
        )

    # TS-101: socket.emit(req.xxx) — user-controlled Socket.IO event name
    if _SOCKET_EMIT_REQ.search(raw):
        _add(
            "TS-101",
            Severity.MEDIUM,
            Confidence.HIGH,
            "socket.emit(req.xxx) — user-controlled event name can trigger unintended server-side handlers",
            "Allowlist permitted event names. Never use request data directly as the socket event.",
        )

    # TS-102: $.ajax({url: req.xxx}) — jQuery SSRF via user-controlled URL
    if _JQUERY_AJAX_URL_REQ.search(raw):
        _add(
            "TS-102",
            Severity.HIGH,
            Confidence.HIGH,
            "$.ajax({url: req.xxx}) — user-controlled URL in jQuery ajax call enables SSRF",
            "Hardcode the target URL or validate it against an allowlist. Never use request data as ajax url.",
        )

    # TS-103: redis.createClient({url: req.xxx}) — SSRF via user-controlled Redis URL
    if _REDIS_CREATE_CLIENT_REQ.search(raw):
        _add(
            "TS-103",
            Severity.HIGH,
            Confidence.HIGH,
            "createClient({url: req.xxx}) — user-controlled Redis URL enables SSRF",
            "Hardcode the Redis URL in configuration. Never allow request data to set the connection URL.",
        )

    # TS-104: amqplib.connect(req.xxx) — SSRF via user-controlled RabbitMQ URL
    if _AMQPLIB_CONNECT_REQ.search(raw):
        _add(
            "TS-104",
            Severity.HIGH,
            Confidence.HIGH,
            "amqplib.connect(req.xxx) — user-controlled URL enables SSRF via RabbitMQ",
            "Hardcode the AMQP broker URL. Never allow callers to supply the connection target.",
        )

    # TS-105: pg.connect(req.xxx) — SSRF via user-controlled PostgreSQL connection string
    if _PG_CONNECT_REQ.search(raw):
        _add(
            "TS-105",
            Severity.HIGH,
            Confidence.HIGH,
            "pg.connect(req.xxx) — user-controlled connection string enables SSRF via PostgreSQL",
            "Hardcode the database connection string. Never allow request data to set it.",
        )

    # TS-106: new WebSocket(req.xxx) — SSRF via user-controlled WebSocket URL
    if _WEBSOCKET_REQ.search(raw):
        _add(
            "TS-106",
            Severity.HIGH,
            Confidence.HIGH,
            "new WebSocket(req.xxx) — user-controlled URL enables SSRF via WebSocket connection",
            "Hardcode the WebSocket server URL. Never allow request data to set the endpoint.",
        )

    # TS-107: new EventSource(req.xxx) — SSRF via user-controlled SSE URL
    if _EVENT_SOURCE_REQ.search(raw):
        _add(
            "TS-107",
            Severity.HIGH,
            Confidence.HIGH,
            "new EventSource(req.xxx) — user-controlled URL enables SSRF via Server-Sent Events",
            "Hardcode the EventSource URL. Never allow request data to set the SSE endpoint.",
        )

    # TS-108: new Client({node: req.xxx}) — SSRF via user-controlled Elasticsearch node URL
    if _ES_CLIENT_NODE_REQ.search(raw):
        _add(
            "TS-108",
            Severity.HIGH,
            Confidence.HIGH,
            "new Client({node: req.xxx}) — user-controlled Elasticsearch node URL enables SSRF",
            "Hardcode the Elasticsearch node URL in configuration. Never allow callers to supply it.",
        )

    # TS-109: res.cookie(req.xxx, ...) — user-controlled cookie name enables header injection
    if _COOKIE_NAME_REQ.search(raw):
        _add(
            "TS-109",
            Severity.MEDIUM,
            Confidence.HIGH,
            "res.cookie(req.xxx, ...) — user-controlled cookie name enables header injection",
            "Hardcode or allowlist the cookie name. Never allow request data to become a cookie name.",
        )

    # TS-110: crypto.scrypt(req.xxx, ...) — DoS via user-controlled password in scrypt
    if _CRYPTO_SCRYPT_REQ.search(raw):
        _add(
            "TS-110",
            Severity.MEDIUM,
            Confidence.HIGH,
            "crypto.scrypt(req.xxx, ...) — user-controlled password in scrypt can cause CPU exhaustion DoS",
            "Enforce a maximum password length before hashing. Never pass unbounded input to scrypt.",
        )

    # TS-111: new URL(req.xxx) — SSRF / open redirect via user-controlled URL constructor
    if _NEW_URL_REQ.search(raw):
        _add(
            "TS-111",
            Severity.MEDIUM,
            Confidence.HIGH,
            "new URL(req.xxx) — user-controlled URL parsed with the URL constructor; validate before use",
            "Allowlist permitted origins. Never construct a URL from request data without validation.",
        )

    # TS-112: mysql.createConnection({host: req.xxx}) — SSRF via MySQL host
    if _MYSQL_CONN_REQ.search(raw):
        _add(
            "TS-112",
            Severity.HIGH,
            Confidence.HIGH,
            "mysql.createConnection({host: req.xxx}) — user-controlled MySQL host enables SSRF",
            "Hardcode or allowlist the MySQL host. Never accept it from request data.",
        )

    # TS-113: new Redis(req.xxx) — SSRF via user-controlled ioredis connection string
    if _IOREDIS_NEW_REQ.search(raw):
        _add(
            "TS-113",
            Severity.HIGH,
            Confidence.HIGH,
            "new Redis(req.xxx) — user-controlled Redis connection string enables SSRF",
            "Hardcode or allowlist the Redis host/URL. Never pass request data to new Redis().",
        )

    # TS-114: createConnection({host: req.xxx}) — SSRF via TypeORM user-controlled host
    if _TYPEORM_CONN_REQ.search(raw):
        _add(
            "TS-114",
            Severity.HIGH,
            Confidence.HIGH,
            "createConnection({host: req.xxx}) — user-controlled TypeORM host enables SSRF",
            "Hardcode the database host. Never let request data determine the connection target.",
        )

    # TS-115: undici.request/fetch(req.xxx) — SSRF via undici HTTP client
    if _UNDICI_REQ.search(raw):
        _add(
            "TS-115",
            Severity.HIGH,
            Confidence.HIGH,
            "undici.request/fetch(req.xxx) — user-controlled URL in undici enables SSRF",
            "Validate the URL against an allowlist. Never pass request data directly to undici.",
        )

    # TS-116: superagent.get/post(req.xxx) — SSRF via superagent user-controlled URL
    if _SUPERAGENT_REQ.search(raw):
        _add(
            "TS-116",
            Severity.HIGH,
            Confidence.HIGH,
            "superagent.*(req.xxx) — user-controlled URL passed to superagent enables SSRF",
            "Validate the URL against an allowlist. Never pass request data directly to superagent.",
        )

    # TS-117: ky(req.xxx) / ky.get(req.xxx) — SSRF via ky HTTP client
    if _KY_REQ.search(raw):
        _add(
            "TS-117",
            Severity.HIGH,
            Confidence.HIGH,
            "ky(req.xxx) — user-controlled URL passed to ky HTTP client enables SSRF",
            "Validate the URL against an allowlist. Never pass request data directly to ky.",
        )

    # TS-118: element.setAttribute("src"|"href", req.xxx) — DOM attribute injection
    if _SET_ATTR_SRC_HREF_REQ.search(raw):
        _add(
            "TS-118",
            Severity.HIGH,
            Confidence.HIGH,
            "setAttribute(src/href/action, req.xxx) — user-controlled DOM attribute enables XSS or open redirect",
            "Allowlist permitted values. Never set src, href or action from request data without validation.",
        )

    # TS-119: location.assign/replace(req.xxx) — open redirect via location methods
    if _LOCATION_ASSIGN_REQ.search(raw):
        _add(
            "TS-119",
            Severity.HIGH,
            Confidence.HIGH,
            "location.assign/replace(req.xxx) — user-controlled URL causes open redirect",
            "Allowlist redirect destinations. Never call location.assign/replace with request data.",
        )

    # TS-120: new S3Client/DynamoDBClient({endpoint: req.xxx}) — AWS SDK SSRF
    if _AWS_SDK_ENDPOINT_REQ.search(raw):
        _add(
            "TS-120",
            Severity.HIGH,
            Confidence.HIGH,
            "new AwsClient({endpoint: req.xxx}) — user-controlled AWS endpoint enables SSRF",
            "Hardcode the endpoint URL or allowlist it. Never accept AWS endpoints from request data.",
        )
    # TS-121: new Kafka({ brokers: req.xxx }) — SSRF via user-controlled KafkaJS brokers
    if _KAFKAJS_BROKERS_REQ.search(raw):
        _add(
            "TS-121",
            Severity.HIGH,
            Confidence.HIGH,
            "new Kafka({brokers: req.xxx}) — user-controlled Kafka brokers enable SSRF",
            "Hardcode Kafka broker addresses. Never accept broker URLs from request data.",
        )
    # TS-122: tls.connect({ host: req.xxx }) — SSRF via user-controlled TLS host
    if _TLS_CONNECT_REQ.search(raw):
        _add(
            "TS-122",
            Severity.HIGH,
            Confidence.HIGH,
            "tls.connect({host: req.xxx}) — user-controlled TLS host enables SSRF",
            "Hardcode the TLS host. Never accept connection targets from request data.",
        )
    # TS-123: nats.connect(req.xxx) — SSRF via user-controlled NATS server URL
    if _NATS_CONNECT_REQ.search(raw):
        _add(
            "TS-123",
            Severity.HIGH,
            Confidence.HIGH,
            "nats.connect(req.xxx) — user-controlled NATS server URL enables SSRF",
            "Hardcode the NATS server URL. Never accept server addresses from request data.",
        )
    # TS-124: new InfluxDB({ url: req.xxx }) — SSRF via user-controlled InfluxDB URL
    if _INFLUXDB_URL_REQ.search(raw):
        _add(
            "TS-124",
            Severity.HIGH,
            Confidence.HIGH,
            "new InfluxDB({url: req.xxx}) — user-controlled InfluxDB URL enables SSRF",
            "Hardcode the InfluxDB URL. Never accept time-series DB URLs from request data.",
        )
    # TS-125: neo4j.driver(req.xxx) — SSRF via user-controlled Neo4j URI
    if _NEO4J_DRIVER_REQ.search(raw):
        _add(
            "TS-125",
            Severity.HIGH,
            Confidence.HIGH,
            "neo4j.driver(req.xxx) — user-controlled Neo4j URI enables SSRF",
            "Hardcode the Neo4j URI. Never accept graph database URIs from request data.",
        )
    # TS-126: new ClickHouse({ host: req.xxx }) — SSRF via user-controlled ClickHouse host
    if _CLICKHOUSE_HOST_REQ.search(raw):
        _add(
            "TS-126",
            Severity.HIGH,
            Confidence.HIGH,
            "new ClickHouse({host: req.xxx}) — user-controlled ClickHouse host enables SSRF",
            "Hardcode the ClickHouse host. Never accept database hosts from request data.",
        )
    # TS-127: new WeaviateClient({ httpHost: req.xxx }) -- Weaviate vector DB SSRF
    if _WEAVIATE_HOST_REQ.search(raw):
        _add(
            "TS-127",
            Severity.HIGH,
            Confidence.HIGH,
            "new WeaviateClient({httpHost: req.xxx}) -- user-controlled Weaviate host enables SSRF",
            "Hardcode the Weaviate host. Never accept vector DB hosts from request data.",
        )
    # TS-128: new QdrantClient({ url: req.xxx }) -- Qdrant vector DB SSRF
    if _QDRANT_URL_REQ.search(raw):
        _add(
            "TS-128",
            Severity.HIGH,
            Confidence.HIGH,
            "new QdrantClient({url: req.xxx}) -- user-controlled Qdrant URL enables SSRF",
            "Hardcode the Qdrant URL. Never accept vector DB URLs from request data.",
        )
    # TS-129: new ChromaClient({ path: req.xxx }) -- ChromaDB SSRF
    if _CHROMA_PATH_REQ.search(raw):
        _add(
            "TS-129",
            Severity.HIGH,
            Confidence.HIGH,
            "new ChromaClient({path: req.xxx}) -- user-controlled ChromaDB path enables SSRF",
            "Hardcode the ChromaDB path. Never accept vector DB paths from request data.",
        )
    # TS-130: new OpenAI({ baseURL: req.xxx }) -- SSRF / API key exfiltration
    if _OPENAI_BASE_URL_REQ.search(raw):
        _add(
            "TS-130",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new OpenAI({baseURL: req.xxx}) -- user-controlled base URL exfiltrates API key to attacker",
            "Hardcode the OpenAI base URL. Never accept AI API URLs from request data.",
        )
    # TS-131: new Anthropic({ baseURL: req.xxx }) -- SSRF / API key exfiltration
    if _ANTHROPIC_BASE_URL_REQ.search(raw):
        _add(
            "TS-131",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new Anthropic({baseURL: req.xxx}) -- user-controlled base URL exfiltrates API key to attacker",
            "Hardcode the Anthropic base URL. Never accept AI API URLs from request data.",
        )
    # TS-132: new MilvusClient({ address: req.xxx }) -- Milvus SSRF
    if _MILVUS_ADDRESS_REQ.search(raw):
        _add(
            "TS-132",
            Severity.HIGH,
            Confidence.HIGH,
            "new MilvusClient({address: req.xxx}) -- user-controlled Milvus address enables SSRF",
            "Hardcode the Milvus address. Never accept vector DB addresses from request data.",
        )
    # TS-133: new Groq({ baseURL: req.xxx }) -- SSRF / API key exfiltration
    if _GROQ_BASE_URL_REQ.search(raw):
        _add(
            "TS-133",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new Groq({baseURL: req.xxx}) -- user-controlled base URL exfiltrates API key to attacker",
            "Hardcode the Groq base URL. Never accept AI API URLs from request data.",
        )
    # TS-134: new CohereClient({ baseURL: req.xxx }) -- SSRF / API key exfiltration
    if _COHERE_BASE_URL_REQ.search(raw):
        _add(
            "TS-134",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new CohereClient({baseURL: req.xxx}) -- user-controlled base URL exfiltrates API key",
            "Hardcode the Cohere base URL. Never accept AI API URLs from request data.",
        )
    # TS-135: new MistralClient({ serverURL: req.xxx }) -- SSRF / API key exfiltration
    if _MISTRAL_SERVER_URL_REQ.search(raw):
        _add(
            "TS-135",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new MistralClient({serverURL: req.xxx}) -- user-controlled server URL exfiltrates API key",
            "Hardcode the Mistral server URL. Never accept AI API URLs from request data.",
        )
    # TS-136: new Together({ baseURL: req.xxx }) -- SSRF / API key exfiltration
    if _TOGETHER_BASE_URL_REQ.search(raw):
        _add(
            "TS-136",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new Together({baseURL: req.xxx}) -- user-controlled base URL exfiltrates API key",
            "Hardcode the Together AI base URL. Never accept AI API URLs from request data.",
        )
    # TS-137: new ReplicateClient({ baseURL: req.xxx }) -- SSRF / API key exfiltration
    if _REPLICATE_BASE_URL_REQ.search(raw):
        _add(
            "TS-137",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new ReplicateClient({baseURL: req.xxx}) -- user-controlled base URL exfiltrates API key",
            "Hardcode the Replicate base URL. Never accept AI API URLs from request data.",
        )
    # TS-138: new HuggingFaceInference({ baseURL: req.xxx }) -- SSRF / API key exfiltration
    if _HF_INFERENCE_BASE_URL_REQ.search(raw):
        _add(
            "TS-138",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new HuggingFaceInference({baseURL: req.xxx}) -- user-controlled base URL exfiltrates API key",
            "Hardcode the HuggingFace endpoint. Never accept AI API URLs from request data.",
        )
    # TS-139: new VoyageAI({ baseURL: req.xxx }) -- SSRF / API key exfiltration
    if _VOYAGE_BASE_URL_REQ.search(raw):
        _add(
            "TS-139",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new VoyageAI({baseURL: req.xxx}) -- user-controlled base URL exfiltrates API key",
            "Hardcode the Voyage AI base URL. Never accept AI API URLs from request data.",
        )
    # TS-140: new AzureOpenAI({ endpoint: req.xxx }) -- SSRF / API key exfiltration
    if _AZURE_OPENAI_ENDPOINT_REQ.search(raw):
        _add(
            "TS-140",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new AzureOpenAI({endpoint: req.xxx}) -- user-controlled endpoint exfiltrates API key",
            "Hardcode the Azure AI endpoint. Never accept AI API endpoints from request data.",
        )
    # TS-141: new AI21({ baseURL: req.xxx }) -- SSRF / API key exfiltration
    if _AI21_BASE_URL_REQ.search(raw):
        _add(
            "TS-141",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new AI21({baseURL: req.xxx}) -- user-controlled base URL exfiltrates API key",
            "Hardcode the AI21 Labs base URL. Never accept AI API URLs from request data.",
        )
    # TS-142: axios.create({ baseURL: req.xxx }) -- SSRF via axios instance base URL
    if _AXIOS_CREATE_BASE_URL_REQ.search(raw):
        _add(
            "TS-142",
            Severity.HIGH,
            Confidence.HIGH,
            "axios.create({baseURL: req.xxx}) -- user-controlled base URL poisons all requests from this instance",
            "Hardcode the base URL in axios.create(). Never accept HTTP base URLs from request data.",
        )
    # TS-143: new Cerebras({ baseURL: req.xxx }) -- Cerebras AI SSRF / API key exfiltration
    if _CEREBRAS_BASE_URL_REQ.search(raw):
        _add(
            "TS-143",
            Severity.CRITICAL,
            Confidence.HIGH,
            "new Cerebras({baseURL: req.xxx}) -- user-controlled base URL exfiltrates API key",
            "Hardcode the Cerebras base URL. Never accept AI API URLs from request data.",
        )
    # TS-144: new BlobServiceClient(req.xxx) -- Azure Blob SSRF via user-controlled URL
    if _BLOB_SERVICE_CLIENT_URL_REQ.search(raw):
        _add(
            "TS-144",
            Severity.HIGH,
            Confidence.HIGH,
            "new BlobServiceClient(req.xxx) -- user-controlled Azure Blob URL enables SSRF",
            "Hardcode the Azure storage account URL. Never let request data set cloud storage URLs.",
        )
    # TS-145: new Storage({ apiEndpoint: req.xxx }) -- Google Cloud Storage SSRF
    if _GCS_API_ENDPOINT_REQ.search(raw):
        _add(
            "TS-145",
            Severity.HIGH,
            Confidence.HIGH,
            "new Storage({apiEndpoint: req.xxx}) -- user-controlled GCS endpoint enables SSRF",
            "Hardcode the Google Cloud Storage endpoint. Never let request data set cloud endpoints.",
        )
    # TS-146: initializeApp({ databaseURL: req.xxx }) -- Firebase SSRF
    if _FIREBASE_DATABASE_URL_REQ.search(raw):
        _add(
            "TS-146",
            Severity.HIGH,
            Confidence.HIGH,
            "initializeApp({databaseURL: req.xxx}) -- user-controlled Firebase database URL enables SSRF",
            "Hardcode the Firebase databaseURL. Never let request data set Firebase app options.",
        )
    # TS-147: new BigQuery({ apiEndpoint: req.xxx }) -- Google BigQuery SSRF
    if _BIGQUERY_API_ENDPOINT_REQ.search(raw):
        _add(
            "TS-147",
            Severity.HIGH,
            Confidence.HIGH,
            "new BigQuery({apiEndpoint: req.xxx}) -- user-controlled BigQuery endpoint enables SSRF",
            "Hardcode the BigQuery endpoint. Never let request data set cloud endpoints.",
        )

    if _OBJ_DEFINE_PROP_REQ.search(raw):
        _add(
            "TS-067",
            Severity.HIGH,
            Confidence.HIGH,
            "Object.defineProperty(obj, req.xxx, ...) — user-controlled property name enables prototype pollution",
            "Allowlist property names. Never let callers choose what property to define on an object.",
        )

    # TS-068: crypto.createCipheriv/createDecipheriv with user-controlled algorithm
    if _CRYPTO_CIPHER_ALGO_REQ.search(raw):
        _add(
            "TS-068",
            Severity.MEDIUM,
            Confidence.HIGH,
            "crypto.createCipheriv(req.xxx, ...) — user-controlled cipher algorithm enables algorithm confusion",
            "Hardcode the cipher algorithm (e.g. 'aes-256-gcm'). Never let callers choose the cipher.",
        )

    # TS-069: fs.writeFileSync(req.xxx, data) — synchronous write path traversal
    if _WRITE_FILE_SYNC_REQ.search(raw):
        _add(
            "TS-069",
            Severity.HIGH,
            Confidence.HIGH,
            "fs.writeFileSync(req.xxx, ...) — user-controlled path allows writing arbitrary server files",
            "Validate the path against an allowlist or use path.resolve + prefix check to prevent traversal.",
        )

    # TS-064: document.write(req.xxx) — DOM XSS via document.write
    if _DOC_WRITE_REQ.search(raw):
        _add(
            "TS-064",
            Severity.HIGH,
            Confidence.HIGH,
            "document.write(req.xxx) — user-controlled HTML injected into the document bypasses CSP",
            "Never use document.write(). Use textContent or a safe DOM API to insert dynamic content.",
        )

    # TS-065: window.open(req.xxx) — DOM open redirect
    if _WINDOW_OPEN_REQ.search(raw):
        _add(
            "TS-065",
            Severity.MEDIUM,
            Confidence.HIGH,
            "window.open(req.xxx) — user-controlled URL opens an arbitrary site (open redirect / phishing)",
            "Validate the URL against an allowlist before calling window.open().",
        )

    # TS-066: $(el).html(req.xxx) — jQuery innerHTML injection
    if _JQUERY_HTML_REQ.search(raw):
        _add(
            "TS-066",
            Severity.HIGH,
            Confidence.HIGH,
            "$(el).html(req.xxx) — user-controlled HTML injected via jQuery .html() enables XSS",
            "Use .text() for plain-text content or sanitize HTML with DOMPurify before calling .html().",
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
