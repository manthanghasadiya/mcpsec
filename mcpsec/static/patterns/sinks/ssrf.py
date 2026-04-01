"""
SSRF (Server-Side Request Forgery) patterns -- ~100 patterns across 5 languages.

Coverage:
- TypeScript/JavaScript: fetch(), axios, request, http.get(), got, node-fetch
- Python: requests.*, urllib, httpx, aiohttp
- Go: http.Get(), http.NewRequest()
- C#: HttpClient, WebClient, WebRequest
- Rust: reqwest
"""

from mcpsec.static.patterns.base import (
    SinkPattern, Language, VulnType, Severity, Confidence
)

PATTERNS: list[SinkPattern] = []

# ==============================================================================
# TYPESCRIPT / JAVASCRIPT
# ==============================================================================

# -- fetch() --
PATTERNS.extend([
    SinkPattern(
        id="js-ssrf-001",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bfetch\s*\(\s*[^'\"`\s][^,)]*",
        function_name="fetch(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="fetch() with variable URL -- potential SSRF",
        cwe="CWE-918",
        remediation="Validate and allowlist URLs before making requests",
        negative_patterns=[r"fetch\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-ssrf-002",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bfetch\s*\(\s*`[^`]*\$\{[^}]+\}",
        function_name="fetch(`${url}`)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="fetch() with template literal URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="js-ssrf-003",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bfetch\s*\([^)]*\+[^)]*\)",
        function_name="fetch(concat)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="fetch() with concatenated URL",
        cwe="CWE-918",
        negative_patterns=[r"fetch\s*\(\s*['\"`]"],
    ),
])

# -- axios --
PATTERNS.extend([
    SinkPattern(
        id="js-ssrf-010",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\baxios\.\w+\s*\(\s*[^'\"`\s][^,)]*",
        function_name="axios.get/post(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="axios request with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"axios\.\w+\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-ssrf-011",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\baxios\.\w+\s*\(\s*`[^`]*\$\{[^}]+\}",
        function_name="axios.get/post(`${}`)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="axios request with template literal URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="js-ssrf-012",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"axios\s*\(\s*\{\s*url\s*:\s*[^'\"`\s][^,}]*",
        function_name="axios({url: variable})",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="axios config with variable url",
        cwe="CWE-918",
        negative_patterns=[r"url\s*:\s*['\"`]"],
    ),
])

# -- http.get / http.request --
PATTERNS.extend([
    SinkPattern(
        id="js-ssrf-020",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bhttp(?:s)?\.get\s*\(\s*[^'\"`\s][^,)]*",
        function_name="http.get(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="node http.get with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"http(?:s)?\.get\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-ssrf-021",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bhttp(?:s)?\.request\s*\(\s*[^'\"`\s][^,)]*",
        function_name="http.request(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="node http.request with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"http(?:s)?\.request\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-ssrf-022",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bhttp(?:s)?\.get\s*\(\s*`[^`]*\$\{[^}]+\}",
        function_name="http.get(`${}`)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="http.get with template literal URL",
        cwe="CWE-918",
    ),
])

# -- got, node-fetch, superagent, request --
PATTERNS.extend([
    SinkPattern(
        id="js-ssrf-030",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bgot\s*\.\w*\s*\(\s*[^'\"`\s][^,)]*",
        function_name="got.get/post(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="got HTTP library with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"got\.\w*\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-ssrf-031",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bgot\s*\(\s*`[^`]*\$\{[^}]+\}",
        function_name="got(`${url}`)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="got() with template literal URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="js-ssrf-032",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\brequest\s*\.\w+\s*\(\s*[^'\"`\s][^,)]*",
        function_name="request.get/post(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="request library with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"request\.\w+\s*\(\s*['\"`]"],
    ),
    SinkPattern(
        id="js-ssrf-033",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bsuperagent\.\w+\s*\(\s*[^'\"`\s][^,)]*",
        function_name="superagent.get(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="superagent with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"superagent\.\w+\s*\(\s*['\"`]"],
    ),
])

# -- XMLHttpRequest / WebSocket --
PATTERNS.extend([
    SinkPattern(
        id="js-ssrf-040",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\.open\s*\(\s*['\"][^'\"]*['\"].*,\s*[^'\"`\s][^,)]*",
        function_name="xhr.open(method, variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="XMLHttpRequest.open with variable URL",
        cwe="CWE-918",
        context_patterns=[r"XMLHttpRequest"],
    ),
    SinkPattern(
        id="js-ssrf-041",
        vuln_type=VulnType.SSRF,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bnew\s+WebSocket\s*\(\s*[^'\"`\s][^)]*\)",
        function_name="new WebSocket(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="WebSocket connection with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"new\s+WebSocket\s*\(\s*['\"`]"],
    ),
])

# ==============================================================================
# PYTHON
# ==============================================================================

# -- requests --
PATTERNS.extend([
    SinkPattern(
        id="py-ssrf-001",
        vuln_type=VulnType.SSRF,
        languages=[Language.PYTHON],
        pattern=r"\brequests\.\w+\s*\(\s*(?:url\s*=\s*)?[^'\"\s][^,)]*",
        function_name="requests.get/post(url)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="requests library with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"requests\.\w+\s*\(\s*['\"]"],
    ),
    SinkPattern(
        id="py-ssrf-002",
        vuln_type=VulnType.SSRF,
        languages=[Language.PYTHON],
        pattern=r"\brequests\.\w+\s*\(\s*f['\"]",
        function_name="requests.get(f-string url)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="requests with f-string URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="py-ssrf-003",
        vuln_type=VulnType.SSRF,
        languages=[Language.PYTHON],
        pattern=r"\brequests\.Session\(\)\.get\s*\(\s*f['\"]",
        function_name="Session().get(f-string)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="requests Session with f-string URL",
        cwe="CWE-918",
    ),
])

# -- urllib --
PATTERNS.extend([
    SinkPattern(
        id="py-ssrf-010",
        vuln_type=VulnType.SSRF,
        languages=[Language.PYTHON],
        pattern=r"\burllib\.request\.urlopen\s*\(\s*[^'\"\s][^)]*\)",
        function_name="urllib.request.urlopen(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="urllib urlopen with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"urlopen\s*\(\s*['\"]"],
    ),
    SinkPattern(
        id="py-ssrf-011",
        vuln_type=VulnType.SSRF,
        languages=[Language.PYTHON],
        pattern=r"\burllib\.request\.urlopen\s*\(\s*f['\"]",
        function_name="urllib.urlopen(f-string)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="urllib urlopen with f-string URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="py-ssrf-012",
        vuln_type=VulnType.SSRF,
        languages=[Language.PYTHON],
        pattern=r"\burllib\.request\.Request\s*\(\s*[^'\"\s][^)]*\)",
        function_name="urllib.Request(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="urllib.Request with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"Request\s*\(\s*['\"]"],
    ),
])

# -- httpx / aiohttp --
PATTERNS.extend([
    SinkPattern(
        id="py-ssrf-020",
        vuln_type=VulnType.SSRF,
        languages=[Language.PYTHON],
        pattern=r"\bhttpx\.\w+\s*\(\s*f['\"]",
        function_name="httpx.get(f-string)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="httpx with f-string URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="py-ssrf-021",
        vuln_type=VulnType.SSRF,
        languages=[Language.PYTHON],
        pattern=r"\bhttpx\.AsyncClient\(\).*\.\w+\s*\(\s*f['\"]",
        function_name="httpx.AsyncClient().get(f-string)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="httpx async client with f-string URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="py-ssrf-022",
        vuln_type=VulnType.SSRF,
        languages=[Language.PYTHON],
        pattern=r"\baiohttp\.ClientSession\b",
        function_name="aiohttp.ClientSession(variable)",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="aiohttp ClientSession -- check URL source",
        cwe="CWE-918",
    ),
])

# ==============================================================================
# GO
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="go-ssrf-001",
        vuln_type=VulnType.SSRF,
        languages=[Language.GO],
        pattern=r"\bhttp\.Get\s*\(\s*[^\"'][^)]*\)",
        function_name="http.Get(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="http.Get with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"http\.Get\s*\(\s*\""],
    ),
    SinkPattern(
        id="go-ssrf-002",
        vuln_type=VulnType.SSRF,
        languages=[Language.GO],
        pattern=r"\bhttp\.Get\s*\(\s*fmt\.Sprintf\s*\(",
        function_name="http.Get(Sprintf())",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="http.Get with Sprintf URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="go-ssrf-003",
        vuln_type=VulnType.SSRF,
        languages=[Language.GO],
        pattern=r"\bhttp\.NewRequest\s*\(\s*[^,]+,\s*[^\"'][^,)]*",
        function_name="http.NewRequest(method, variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="http.NewRequest with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"http\.NewRequest\s*\([^,]+,\s*\""],
    ),
    SinkPattern(
        id="go-ssrf-004",
        vuln_type=VulnType.SSRF,
        languages=[Language.GO],
        pattern=r"\bhttp\.Post\s*\(\s*[^\"'][^,)]*",
        function_name="http.Post(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="http.Post with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"http\.Post\s*\(\s*\""],
    ),
])

# ==============================================================================
# C# / .NET
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="cs-ssrf-001",
        vuln_type=VulnType.SSRF,
        languages=[Language.CSHARP],
        pattern=r"new\s+HttpClient\s*\(\s*\).*\.GetAsync\s*\(\s*[^@\"'][^)]*\)",
        function_name="HttpClient.GetAsync(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="HttpClient.GetAsync with variable URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="cs-ssrf-002",
        vuln_type=VulnType.SSRF,
        languages=[Language.CSHARP],
        pattern=r"\.GetAsync\s*\(\s*\$\"",
        function_name="GetAsync($\"...\")",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="HttpClient.GetAsync with interpolated URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="cs-ssrf-003",
        vuln_type=VulnType.SSRF,
        languages=[Language.CSHARP],
        pattern=r"WebRequest\.Create\s*\(\s*[^@\"'][^)]*\)",
        function_name="WebRequest.Create(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="WebRequest.Create with variable URL",
        cwe="CWE-918",
    ),
    SinkPattern(
        id="cs-ssrf-004",
        vuln_type=VulnType.SSRF,
        languages=[Language.CSHARP],
        pattern=r"new\s+WebClient\s*\(\s*\).*\.DownloadString\s*\(",
        function_name="WebClient.DownloadString()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="WebClient.DownloadString -- check URL source",
        cwe="CWE-918",
    ),
])

# ==============================================================================
# RUST
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="rs-ssrf-001",
        vuln_type=VulnType.SSRF,
        languages=[Language.RUST],
        pattern=r"\breqwest::get\s*\(\s*&?\w",
        function_name="reqwest::get(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="reqwest::get with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"reqwest::get\s*\(\s*\""],
    ),
    SinkPattern(
        id="rs-ssrf-002",
        vuln_type=VulnType.SSRF,
        languages=[Language.RUST],
        pattern=r"\bClient::new\(\).*\.get\s*\(\s*&?\w",
        function_name="Client::new().get(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="reqwest Client::get with variable URL",
        cwe="CWE-918",
        negative_patterns=[r"\.get\s*\(\s*\""],
    ),
    SinkPattern(
        id="rs-ssrf-003",
        vuln_type=VulnType.SSRF,
        languages=[Language.RUST],
        pattern=r'format!\s*\(\s*"https?://',
        function_name="format!(\"http://{}\")",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="URL constructed with format! macro",
        cwe="CWE-918",
    ),
])

PATTERN_COUNT = len(PATTERNS)
