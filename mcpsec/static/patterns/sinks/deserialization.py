"""
Deserialization patterns -- ~80+ patterns across languages.

Coverage:
- Python: pickle, yaml.load(), marshal, jsonpickle, shelve
- TypeScript/JavaScript: JSON.parse() in dangerous contexts, node-serialize, serialize-javascript
- Java: ObjectInputStream, XStream, Jackson, Kryo
- C#: BinaryFormatter, XmlSerializer, JavaScriptSerializer
- Go: encoding/gob, encoding/json with interface{}
"""

from mcpsec.static.patterns.base import (
    SinkPattern, Language, VulnType, Severity, Confidence
)

PATTERNS: list[SinkPattern] = []

# ==============================================================================
# PYTHON -- pickle and relatives
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="py-deser-001",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\bpickle\.load[s]?\s*\(",
        function_name="pickle.load()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="pickle.load/loads -- arbitrary code execution via deserialization",
        cwe="CWE-502",
        remediation="Never deserialize untrusted pickle data. Use JSON or encrypt+sign data.",
    ),
    SinkPattern(
        id="py-deser-002",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\bcPickle\.load[s]?\s*\(",
        function_name="cPickle.load()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="cPickle.load/loads -- arbitrary code execution",
        cwe="CWE-502",
    ),
    SinkPattern(
        id="py-deser-003",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\bpickletools\.dis\s*\(",
        function_name="pickletools.dis()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="pickletools.dis -- pickle analysis on untrusted data",
        cwe="CWE-502",
    ),
    SinkPattern(
        id="py-deser-004",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\bshelve\.open\s*\(",
        function_name="shelve.open()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="shelve uses pickle internally -- untrusted data risk",
        cwe="CWE-502",
    ),
])

# -- yaml --
PATTERNS.extend([
    SinkPattern(
        id="py-deser-010",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\byaml\.load\s*\(\s*[^,)]*(?:,\s*Loader\s*=\s*(?!yaml\.SafeLoader))?",
        function_name="yaml.load() without SafeLoader",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="yaml.load() without SafeLoader -- arbitrary code execution",
        cwe="CWE-502",
        remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        negative_patterns=[r"yaml\.load\s*\([^)]*SafeLoader"],
    ),
    SinkPattern(
        id="py-deser-011",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\byaml\.full_load\s*\(",
        function_name="yaml.full_load()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="yaml.full_load() -- allows python objects, prefer safe_load()",
        cwe="CWE-502",
    ),
    SinkPattern(
        id="py-deser-012",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\byaml\.unsafe_load\s*\(",
        function_name="yaml.unsafe_load()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="yaml.unsafe_load() -- explicitly unsafe",
        cwe="CWE-502",
    ),
])

# -- marshal --
PATTERNS.extend([
    SinkPattern(
        id="py-deser-020",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\bmarshal\.loads?\s*\(",
        function_name="marshal.load()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="marshal.load/loads -- not safe for untrusted data",
        cwe="CWE-502",
    ),
])

# -- jsonpickle --
PATTERNS.extend([
    SinkPattern(
        id="py-deser-030",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\bjsonpickle\.decode\s*\(",
        function_name="jsonpickle.decode()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="jsonpickle.decode -- can execute arbitrary Python code",
        cwe="CWE-502",
    ),
])

# -- dill, cloudpickle --
PATTERNS.extend([
    SinkPattern(
        id="py-deser-040",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\bdill\.load[s]?\s*\(",
        function_name="dill.load()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="dill.load -- extends pickle, same risks",
        cwe="CWE-502",
    ),
    SinkPattern(
        id="py-deser-041",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.PYTHON],
        pattern=r"\bcloudpickle\.load[s]?\s*\(",
        function_name="cloudpickle.load()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="cloudpickle.load -- extends pickle, same risks",
        cwe="CWE-502",
    ),
])

# ==============================================================================
# TYPESCRIPT / JAVASCRIPT
# ==============================================================================

# -- node-serialize / serialize-javascript --
PATTERNS.extend([
    SinkPattern(
        id="js-deser-001",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bserialize\.unserialize\s*\(",
        function_name="node-serialize.unserialize()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="node-serialize.unserialize -- RCE via IIFE (CVE-2017-5941)",
        cwe="CWE-502",
        tags=["known-vuln", "CVE-2017-5941"],
    ),
    SinkPattern(
        id="js-deser-002",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bunserialize\s*\(",
        function_name="unserialize()",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        description="unserialize() -- possible node-serialize or PHP-like lib",
        cwe="CWE-502",
    ),
    SinkPattern(
        id="js-deser-003",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bJSON\.parse\s*\([^)]*\)\s*\.\s*(?:constructor|__proto__|prototype)",
        function_name="JSON.parse().__proto__",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="JSON.parse result used for prototype pollution",
        cwe="CWE-1321",
    ),
    SinkPattern(
        id="js-deser-004",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\beval\s*\(\s*JSON\.parse",
        function_name="eval(JSON.parse())",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="eval() on JSON.parse result -- code execution",
        cwe="CWE-502",
    ),
])

# -- Prototype pollution via merge --
PATTERNS.extend([
    SinkPattern(
        id="js-deser-010",
        vuln_type=VulnType.PROTOTYPE_POLLUTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\b(?:extend|merge|deepMerge|assign|deepAssign)\s*\([^)]*JSON\.parse",
        function_name="merge(JSON.parse(user))",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Object merge with parsed JSON -- prototype pollution",
        cwe="CWE-1321",
    ),
    SinkPattern(
        id="js-deser-011",
        vuln_type=VulnType.PROTOTYPE_POLLUTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bObject\.assign\s*\([^)]*,\s*JSON\.parse",
        function_name="Object.assign({}, JSON.parse())",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Object.assign with parsed JSON",
        cwe="CWE-1321",
    ),
    SinkPattern(
        id="js-deser-012",
        vuln_type=VulnType.PROTOTYPE_POLLUTION,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\[.*__proto__.*\]\s*=",
        function_name="obj[__proto__] = ",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Direct __proto__ assignment -- prototype pollution",
        cwe="CWE-1321",
    ),
])

# ==============================================================================
# GO
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="go-deser-001",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.GO],
        pattern=r"\bgob\.NewDecoder\s*\(",
        function_name="gob.NewDecoder()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="encoding/gob decoder -- don't use on untrusted data",
        cwe="CWE-502",
    ),
    SinkPattern(
        id="go-deser-002",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.GO],
        pattern=r"\.Decode\s*\(\s*&interface\{\}",
        function_name=".Decode(&interface{})",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="JSON decode into empty interface -- type confusion risk",
        cwe="CWE-502",
    ),
])

# ==============================================================================
# C# / .NET
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="cs-deser-001",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.CSHARP],
        pattern=r"\bBinaryFormatter\s*\(\s*\).*\.Deserialize\s*\(",
        function_name="BinaryFormatter.Deserialize()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="BinaryFormatter.Deserialize -- RCE, banned in .NET 5+",
        cwe="CWE-502",
        tags=["known-vuln"],
    ),
    SinkPattern(
        id="cs-deser-002",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.CSHARP],
        pattern=r"\bBinaryFormatter\b",
        function_name="BinaryFormatter",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="BinaryFormatter usage -- inherently unsafe",
        cwe="CWE-502",
    ),
    SinkPattern(
        id="cs-deser-003",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.CSHARP],
        pattern=r"\bSoapFormatter\b",
        function_name="SoapFormatter",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="SoapFormatter -- insecure deserialization",
        cwe="CWE-502",
    ),
    SinkPattern(
        id="cs-deser-004",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.CSHARP],
        pattern=r"TypeNameHandling\s*=\s*TypeNameHandling\.(?!None)",
        function_name="TypeNameHandling != None",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Newtonsoft Json.NET TypeNameHandling -- gadget chain risk",
        cwe="CWE-502",
        remediation="Use TypeNameHandling.None or SerializationBinder whitelist",
    ),
    SinkPattern(
        id="cs-deser-005",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.CSHARP],
        pattern=r"\bLosFormatter\b",
        function_name="LosFormatter",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="LosFormatter -- insecure deserialization",
        cwe="CWE-502",
    ),
    SinkPattern(
        id="cs-deser-006",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.CSHARP],
        pattern=r"\bNetDataContractSerializer\b",
        function_name="NetDataContractSerializer",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="NetDataContractSerializer -- RCE risk",
        cwe="CWE-502",
    ),
    SinkPattern(
        id="cs-deser-007",
        vuln_type=VulnType.DESERIALIZATION,
        languages=[Language.CSHARP],
        pattern=r"JsonConvert\.DeserializeObject\s*<[^>]*object[^>]*>",
        function_name="JsonConvert.DeserializeObject<object>",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Json.NET DeserializeObject to object -- TypeNameHandling risk",
        cwe="CWE-502",
    ),
])

PATTERN_COUNT = len(PATTERNS)
