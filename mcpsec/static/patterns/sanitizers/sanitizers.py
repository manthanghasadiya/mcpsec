"""
Sanitizer patterns -- functions that neutralize taint.
"""

from mcpsec.static.patterns.base import (
    SanitizerPattern, Language, VulnType
)

PATTERNS: list[SanitizerPattern] = [
    # ── Type casting (neutralizes injection) ─────────────────────────────
    SanitizerPattern(
        id="san-001",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\b(?:parseInt|parseFloat|Number)\s*\(",
        sanitizes=[VulnType.COMMAND_INJECTION, VulnType.SQL_INJECTION],
        description="Type casting to number",
    ),
    SanitizerPattern(
        id="san-002",
        languages=[Language.PYTHON],
        pattern=r"\b(?:int|float|bool)\s*\(",
        sanitizes=[VulnType.COMMAND_INJECTION, VulnType.SQL_INJECTION],
        description="Python type casting",
    ),
    SanitizerPattern(
        id="san-003",
        languages=[Language.GO],
        pattern=r"\bstrconv\.(?:Atoi|ParseInt|ParseFloat)\s*\(",
        sanitizes=[VulnType.COMMAND_INJECTION, VulnType.SQL_INJECTION],
        description="Go strconv numeric parsing",
    ),
    SanitizerPattern(
        id="san-004",
        languages=[Language.RUST],
        pattern=r"\.parse::<(?:u|i)\d+>\s*\(\s*\)",
        sanitizes=[VulnType.COMMAND_INJECTION, VulnType.SQL_INJECTION],
        description="Rust numeric parse",
    ),

    # ── Shell escaping ────────────────────────────────────────────────────
    SanitizerPattern(
        id="san-010",
        languages=[Language.PYTHON],
        pattern=r"\bshlex\.quote\s*\(",
        sanitizes=[VulnType.COMMAND_INJECTION],
        description="shlex.quote() -- proper shell escaping",
    ),
    SanitizerPattern(
        id="san-011",
        languages=[Language.PYTHON],
        pattern=r"\bshlex\.split\s*\(",
        sanitizes=[VulnType.COMMAND_INJECTION],
        description="shlex.split() -- safe argument parsing",
    ),
    SanitizerPattern(
        id="san-012",
        languages=[Language.PHP],
        pattern=r"\bescapeshellarg\s*\(",
        sanitizes=[VulnType.COMMAND_INJECTION],
        description="escapeshellarg()",
    ),
    SanitizerPattern(
        id="san-013",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bshellEscape\s*\(",
        sanitizes=[VulnType.COMMAND_INJECTION],
        description="shell-escape npm package",
    ),

    # ── Path sanitization ─────────────────────────────────────────────────
    SanitizerPattern(
        id="san-020",
        languages=[Language.PYTHON],
        pattern=r"\bos\.path\.(?:realpath|abspath)\s*\(",
        sanitizes=[VulnType.PATH_TRAVERSAL],
        description="Path canonicalization",
        is_partial=True,
    ),
    SanitizerPattern(
        id="san-021",
        languages=[Language.PYTHON],
        pattern=r"\.resolve\s*\(\s*\).*\.is_relative_to\s*\(",
        sanitizes=[VulnType.PATH_TRAVERSAL],
        description="Path.resolve() + is_relative_to() check",
    ),
    SanitizerPattern(
        id="san-022",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bpath\.(?:normalize|resolve)\s*\(",
        sanitizes=[VulnType.PATH_TRAVERSAL],
        description="path.normalize/resolve",
        is_partial=True,
    ),
    SanitizerPattern(
        id="san-023",
        languages=[Language.GO],
        pattern=r"\bfilepath\.Clean\s*\(",
        sanitizes=[VulnType.PATH_TRAVERSAL],
        description="filepath.Clean()",
        is_partial=True,
    ),
    SanitizerPattern(
        id="san-024",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\.startsWith\s*\(\s*(?:baseDir|rootDir|uploadDir|__dirname)",
        sanitizes=[VulnType.PATH_TRAVERSAL],
        description="Path containment check via startsWith",
    ),
    SanitizerPattern(
        id="san-025",
        languages=[Language.PYTHON],
        pattern=r"\.startswith\s*\(\s*(?:base_dir|root_dir|upload_dir)",
        sanitizes=[VulnType.PATH_TRAVERSAL],
        description="Python path containment check",
    ),
    SanitizerPattern(
        id="san-026",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\.\.\./g",
        sanitizes=[VulnType.PATH_TRAVERSAL],
        description="Regex pattern stripping directory traversal sequences",
    ),

    # ── SQL parameterization ──────────────────────────────────────────────
    SanitizerPattern(
        id="san-030",
        languages=[Language.PYTHON],
        pattern=r"\.execute\s*\([^)]*,\s*[\[(]",
        sanitizes=[VulnType.SQL_INJECTION],
        description="Parameterized query with tuple/list",
    ),
    SanitizerPattern(
        id="san-031",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\.query\s*\([^)]*,\s*\[",
        sanitizes=[VulnType.SQL_INJECTION],
        description="Parameterized query with array",
    ),
    SanitizerPattern(
        id="san-032",
        languages=[Language.GO],
        pattern=r"db\.(?:Query|Exec|QueryRow)\s*\([^)]*\$\d+|\?",
        sanitizes=[VulnType.SQL_INJECTION],
        description="Go parameterized query with placeholder",
    ),
    SanitizerPattern(
        id="san-033",
        languages=[Language.PYTHON],
        pattern=r"db\.session\.execute\s*\(text\(",
        sanitizes=[VulnType.SQL_INJECTION],
        description="SQLAlchemy text() parameterized via bindparam",
        is_partial=True,
    ),

    # ── URL validation ────────────────────────────────────────────────────
    SanitizerPattern(
        id="san-040",
        languages=[Language.PYTHON],
        pattern=r"\burllib\.parse\.urlparse\s*\(",
        sanitizes=[VulnType.SSRF],
        description="URL parsing (needs hostname check)",
        is_partial=True,
    ),
    SanitizerPattern(
        id="san-041",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bnew\s+URL\s*\(",
        sanitizes=[VulnType.SSRF],
        description="URL constructor (needs hostname check)",
        is_partial=True,
    ),
    SanitizerPattern(
        id="san-042",
        languages=[Language.PYTHON],
        pattern=r"(?:hostname|netloc)\s+(?:in|not in)\s+(?:ALLOWED|WHITELIST|allowlist)",
        sanitizes=[VulnType.SSRF],
        description="Hostname allowlist check for SSRF",
    ),
    SanitizerPattern(
        id="san-043",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"ALLOWED_HOSTS.*includes\s*\(\s*(?:url|host)\.hostname",
        sanitizes=[VulnType.SSRF],
        description="JavaScript hostname allowlist check",
    ),

    # ── Schema validation (Zod, Pydantic, Joi) ────────────────────────────
    SanitizerPattern(
        id="san-050",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\.(?:parse|safeParse)\s*\(",
        sanitizes=[
            VulnType.COMMAND_INJECTION,
            VulnType.SQL_INJECTION,
            VulnType.PATH_TRAVERSAL,
        ],
        description="Zod schema validation",
        context_patterns=[r"import.*from\s*['\"]zod['\"]"],
    ),
    SanitizerPattern(
        id="san-051",
        languages=[Language.PYTHON],
        pattern=r"class\s+\w+\s*\(\s*(?:pydantic\.)?BaseModel\s*\)",
        sanitizes=[
            VulnType.COMMAND_INJECTION,
            VulnType.SQL_INJECTION,
        ],
        description="Pydantic model validation",
    ),
    SanitizerPattern(
        id="san-052",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"joi\.\w+\s*\(\s*\)\.validate\s*\(",
        sanitizes=[
            VulnType.COMMAND_INJECTION,
            VulnType.SQL_INJECTION,
            VulnType.PATH_TRAVERSAL,
        ],
        description="Joi schema validation",
    ),
    SanitizerPattern(
        id="san-053",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"yup\.\w+\s*\(\s*\)\.validate\s*\(",
        sanitizes=[
            VulnType.COMMAND_INJECTION,
            VulnType.SQL_INJECTION,
        ],
        description="Yup schema validation",
    ),

    # ── XML safety ────────────────────────────────────────────────────────
    SanitizerPattern(
        id="san-060",
        languages=[Language.PYTHON],
        pattern=r"\bdefusedxml\b",
        sanitizes=[VulnType.XXE],
        description="defusedxml library -- safe XML parsing",
    ),
    SanitizerPattern(
        id="san-061",
        languages=[Language.PYTHON],
        pattern=r"etree\.XMLParser\s*\([^)]*resolve_entities\s*=\s*False",
        sanitizes=[VulnType.XXE],
        description="lxml XMLParser with entity resolution disabled",
    ),

    # ── HTML encoding (prevents XSS, log injection) ───────────────────────
    SanitizerPattern(
        id="san-070",
        languages=[Language.PYTHON],
        pattern=r"\bhtml\.escape\s*\(",
        sanitizes=[VulnType.LOG_INJECTION],
        description="Python html.escape()",
    ),
    SanitizerPattern(
        id="san-071",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bencodeURIComponent\s*\(",
        sanitizes=[VulnType.LOG_INJECTION, VulnType.SSRF],
        description="encodeURIComponent() -- URL encoding",
    ),
]

PATTERN_COUNT = len(PATTERNS)
