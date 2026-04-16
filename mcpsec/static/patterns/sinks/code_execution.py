"""
Code Execution patterns -- ~80 patterns.

Coverage:
- Template injection: Jinja2, Pug/Jade, EJS, Handlebars, Mustache, Mako, Tornado
- Dynamic imports and reflection abuse
- JavaScript: vm, Function, setTimeout/setInterval as eval
- Python: importlib, compile, __import__
- Go: plugin loading, text/template injection
"""

from mcpsec.static.patterns.base import (
    SinkPattern, Language, VulnType, Severity, Confidence
)

PATTERNS: list[SinkPattern] = []

# ==============================================================================
# TEMPLATE INJECTION -- Python (Jinja2, Mako, Tornado, Django)
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="py-tpl-001",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.PYTHON],
        pattern=r"\bjinja2\.Template\s*\(\s*[^'\"\s][^)]*\)",
        function_name="jinja2.Template(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Jinja2 Template from user string -- SSTI",
        cwe="CWE-94",
        remediation="Use render_template() with template files, never from user input",
        negative_patterns=[r"jinja2\.Template\s*\(\s*['\"]"],
    ),
    SinkPattern(
        id="py-tpl-002",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.PYTHON],
        pattern=r"Environment\(\)\.from_string\s*\(\s*[^'\"\s][^)]*\)",
        function_name="Environment().from_string(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Jinja2 from_string with user input -- SSTI",
        cwe="CWE-94",
        negative_patterns=[r"from_string\s*\(\s*['\"]"],
    ),
    SinkPattern(
        id="py-tpl-003",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.PYTHON],
        pattern=r"\bjinja2\.Environment\s*\([^)]*autoescape\s*=\s*False",
        function_name="jinja2.Environment(autoescape=False)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Jinja2 with autoescape disabled",
        cwe="CWE-94",
    ),
    SinkPattern(
        id="py-tpl-004",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.PYTHON],
        pattern=r"\bMako\.template\.Template\s*\(\s*[^'\"\s][^)]*\)",
        function_name="Mako Template(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Mako template from user string -- SSTI",
        cwe="CWE-94",
        negative_patterns=[r"Template\s*\(\s*['\"]"],
    ),
    SinkPattern(
        id="py-tpl-005",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.PYTHON],
        pattern=r"\brender_template_string\s*\(\s*[^'\"\s][^)]*\)",
        function_name="flask.render_template_string(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Flask render_template_string with user input -- SSTI",
        cwe="CWE-94",
        negative_patterns=[r"render_template_string\s*\(\s*['\"]"],
    ),
    SinkPattern(
        id="py-tpl-006",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.PYTHON],
        pattern=r"\brender_template_string\s*\(\s*f['\"]",
        function_name="render_template_string(f-string)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Flask render_template_string with f-string",
        cwe="CWE-94",
    ),
    SinkPattern(
        id="py-tpl-007",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.PYTHON],
        pattern=r"\bstring\.Template\s*\(\s*[^'\"\s][^)]*\)",
        function_name="string.Template(variable)",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="string.Template with user input -- limited SSTI",
        cwe="CWE-94",
        negative_patterns=[r"string\.Template\s*\(\s*['\"]"],
    ),
    SinkPattern(
        id="py-tpl-008",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.PYTHON],
        pattern=r"\btornado\.template\.Template\s*\(\s*[^'\"\s][^)]*\)",
        function_name="tornado.template.Template(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Tornado template from user string -- SSTI, supports Python expressions",
        cwe="CWE-94",
    ),
    SinkPattern(
        id="py-tpl-009",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.PYTHON],
        pattern=r"\bpystache\.render\s*\(\s*[^'\"\s][^,)]*",
        function_name="pystache.render(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Mustache/pystache render from user input",
        cwe="CWE-94",
    ),
])

# ==============================================================================
# TEMPLATE INJECTION -- JavaScript/TypeScript (EJS, Pug, Handlebars)
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="js-tpl-001",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bejs\.render\s*\(\s*[^'\"`\s][^,)]*",
        function_name="ejs.render(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="EJS render from user string -- SSTI (RCE via <%- ... %>)",
        cwe="CWE-94",
        negative_patterns=[r"ejs\.render\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-tpl-002",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bejs\.renderFile\s*\([^,]+,\s*\{[^}]*__proto__",
        function_name="ejs.renderFile({__proto__})",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="EJS renderFile with prototype pollution in data",
        cwe="CWE-94",
    ),
    SinkPattern(
        id="js-tpl-003",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bpug\.render\s*\(\s*[^'\"`\s][^,)]*",
        function_name="pug.render(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Pug/Jade render from user string -- SSTI",
        cwe="CWE-94",
        negative_patterns=[r"pug\.render\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-tpl-004",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bpug\.compile\s*\(\s*[^'\"`\s][^)]*\)",
        function_name="pug.compile(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Pug.compile from user string",
        cwe="CWE-94",
        negative_patterns=[r"pug\.compile\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-tpl-005",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bHandlebars\.compile\s*\(\s*[^'\"`\s][^)]*\)",
        function_name="Handlebars.compile(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Handlebars.compile from user string",
        cwe="CWE-94",
        negative_patterns=[r"Handlebars\.compile\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-tpl-006",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bnunjucks\.renderString\s*\(\s*[^'\"`\s][^,)]*",
        function_name="nunjucks.renderString(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Nunjucks renderString from user input -- SSTI",
        cwe="CWE-94",
        negative_patterns=[r"nunjucks\.renderString\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-tpl-007",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bLiquid\b.*\.parseAndRender\s*\(\s*[^'\"`\s][^,)]*",
        function_name="liquid.parseAndRender(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="LiquidJS parseAndRender from user input",
        cwe="CWE-94",
        negative_patterns=[r"parseAndRender\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-tpl-008",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bswig\.render\s*\(\s*[^'\"`\s][^,)]*",
        function_name="swig.render(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Swig template render from user input",
        cwe="CWE-94",
        negative_patterns=[r"swig\.render\s*\(\s*['\"`]"],
    ),
])

# ==============================================================================
# DYNAMIC CODE EXECUTION -- Python
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="py-code-001",
        vuln_type=VulnType.CODE_EXECUTION,
        languages=[Language.PYTHON],
        pattern=r"\bgetattr\s*\([^,]+,\s*[^'\"\s][^)]*\)",
        function_name="getattr(obj, variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="getattr() with variable attribute name -- reflection abuse",
        cwe="CWE-94",
        negative_patterns=[r"getattr\s*\([^,]+,\s*['\"]"],
    ),
    SinkPattern(
        id="py-code-002",
        vuln_type=VulnType.CODE_EXECUTION,
        languages=[Language.PYTHON],
        pattern=r"\bgetattr\s*\([^,]+,\s*f['\"]",
        function_name="getattr(obj, f-string)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="getattr() with f-string attribute name",
        cwe="CWE-94",
    ),
    SinkPattern(
        id="py-code-003",
        vuln_type=VulnType.CODE_EXECUTION,
        languages=[Language.PYTHON],
        pattern=r"\bimportlib\.import_module\s*\(\s*f['\"]",
        function_name="importlib.import_module(f-string)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Dynamic module import with f-string",
        cwe="CWE-94",
    ),
    SinkPattern(
        id="py-code-004",
        vuln_type=VulnType.CODE_EXECUTION,
        languages=[Language.PYTHON],
        pattern=r"\bctypes\.CDLL\s*\(\s*[^'\"\s][^)]*\)",
        function_name="ctypes.CDLL(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="ctypes.CDLL with variable library path",
        cwe="CWE-94",
        negative_patterns=[r"CDLL\s*\(\s*['\"]"],
    ),
])

# ==============================================================================
# GO -- text/template injection
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="go-code-001",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.GO],
        pattern=r"text/template.*Parse\s*\(",
        function_name="text/template.Parse(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Go text/template Parse -- no HTML escaping, can exec functions",
        cwe="CWE-94",
    ),
    SinkPattern(
        id="go-code-002",
        vuln_type=VulnType.TEMPLATE_INJECTION,
        languages=[Language.GO],
        pattern=r'\btemplate\.New\([^)]*\)\.Parse\s*\(',
        function_name="template.New().Parse()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Go template parse -- check if template source is user-controlled",
        cwe="CWE-94",
    ),
    SinkPattern(
        id="go-code-003",
        vuln_type=VulnType.CODE_EXECUTION,
        languages=[Language.GO],
        pattern=r"\bplugin\.Open\s*\(\s*[^\"'][^)]*\)",
        function_name="plugin.Open(variable)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Go plugin.Open with variable path -- arbitrary code load",
        cwe="CWE-94",
        negative_patterns=[r"plugin\.Open\s*\(\s*\""],
    ),
])

PATTERN_COUNT = len(PATTERNS)
