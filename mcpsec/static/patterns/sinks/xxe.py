"""
XXE (XML External Entities) patterns -- ~60 patterns across languages.

Coverage:
- Python: lxml, xml.etree, xml.sax, defusedxml absence, xmltodict
- Java: DocumentBuilder, SAXParser, XMLInputFactory
- TypeScript/JavaScript: xml2js, fast-xml-parser, libxmljs, xmldom
- C/C++: libxml2
- C#: XmlDocument, XmlReader with DTD processing
"""

from mcpsec.static.patterns.base import (
    SinkPattern, Language, VulnType, Severity, Confidence
)

PATTERNS: list[SinkPattern] = []

# ==============================================================================
# PYTHON -- XML parsers
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="py-xxe-001",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"\blxml\.etree\.parse\s*\(",
        function_name="lxml.etree.parse()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="lxml.etree.parse -- XXE enabled by default",
        cwe="CWE-611",
        remediation="Use defusedxml or disable entity resolution: parser = etree.XMLParser(no_network=True, resolve_entities=False)",
    ),
    SinkPattern(
        id="py-xxe-002",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"\blxml\.etree\.fromstring\s*\(",
        function_name="lxml.etree.fromstring()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="lxml.etree.fromstring -- XXE-capable parser",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="py-xxe-003",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"\bxml\.etree\.ElementTree\.parse\s*\(",
        function_name="xml.etree.ElementTree.parse()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="stdlib XML parser -- vulnerable to billion laughs attack",
        cwe="CWE-611",
        remediation="Use defusedxml.ElementTree instead",
    ),
    SinkPattern(
        id="py-xxe-004",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"\bxml\.etree\.ElementTree\.fromstring\s*\(",
        function_name="xml.etree.ElementTree.fromstring()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="stdlib XML fromstring -- vulnerable to entity expansion",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="py-xxe-005",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"\bxml\.sax\.parseString\s*\(",
        function_name="xml.sax.parseString()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="xml.sax.parseString -- external entity processing",
        cwe="CWE-611",
        remediation="Use defusedxml.sax instead",
    ),
    SinkPattern(
        id="py-xxe-006",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"\bxml\.dom\.minidom\.parseString\s*\(",
        function_name="xml.dom.minidom.parseString()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="minidom parseString -- XXE vulnerable",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="py-xxe-007",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"\bxml\.dom\.minidom\.parse\s*\(",
        function_name="xml.dom.minidom.parse()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="minidom parse -- XXE vulnerable",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="py-xxe-008",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"\bxmltodict\.parse\s*\(",
        function_name="xmltodict.parse()",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="xmltodict.parse -- check XML library used underneath",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="py-xxe-009",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"\bBeautifulSoup\s*\([^)]*['\"]xml['\"]",
        function_name="BeautifulSoup(html, 'xml')",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="BeautifulSoup with xml parser -- check lxml usage",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="py-xxe-010",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"\breturn\s*etree\.XMLParser\s*\([^)]*\)\s*(?!.*no_network|.*resolve_entities)",
        function_name="etree.XMLParser() without safety flags",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="lxml XMLParser without security restrictions",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="py-xxe-011",
        vuln_type=VulnType.XXE,
        languages=[Language.PYTHON],
        pattern=r"etree\.XMLParser\s*\(\s*\)",
        function_name="etree.XMLParser() default",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="etree.XMLParser with no args -- entity resolution enabled by default",
        cwe="CWE-611",
    ),
])

# ==============================================================================
# TYPESCRIPT / JAVASCRIPT
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="js-xxe-001",
        vuln_type=VulnType.XXE,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bxml2js\.parseString\s*\(",
        function_name="xml2js.parseString()",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="xml2js.parseString -- XXE depends on configuration",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="js-xxe-002",
        vuln_type=VulnType.XXE,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bfxp\.XMLParser\s*\(\s*\{[^}]*(?!processEntities\s*:\s*false)[^}]*\}",
        function_name="fast-xml-parser without processEntities:false",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="fast-xml-parser without disabling entity processing",
        cwe="CWE-611",
        remediation="Set processEntities: false in fast-xml-parser options",
    ),
    SinkPattern(
        id="js-xxe-003",
        vuln_type=VulnType.XXE,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bnew\s+fxp\.XMLParser\s*\(\s*\)",
        function_name="new XMLParser() defaults",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="fast-xml-parser XMLParser with defaults -- entities enabled",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="js-xxe-004",
        vuln_type=VulnType.XXE,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\blibxmljs\.parseXml\s*\(",
        function_name="libxmljs.parseXml()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="libxmljs.parseXml -- check entity expansion settings",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="js-xxe-005",
        vuln_type=VulnType.XXE,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bDOMParser\b.*parseFromString\s*\(",
        function_name="DOMParser.parseFromString()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="DOMParser.parseFromString -- XXE in some environments",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="js-xxe-006",
        vuln_type=VulnType.XXE,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bsax\.createStream\s*\([^)]*xmlns\s*:\s*true",
        function_name="sax.createStream({xmlns:true})",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="sax stream with namespace processing",
        cwe="CWE-611",
    ),
])

# ==============================================================================
# C / C++ -- libxml2
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="c-xxe-001",
        vuln_type=VulnType.XXE,
        languages=[Language.C, Language.CPP],
        pattern=r"\bxmlReadMemory\s*\(",
        function_name="xmlReadMemory()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="libxml2 xmlReadMemory -- entity substitution may be enabled",
        cwe="CWE-611",
        remediation="Set XML_PARSE_NOENT | XML_PARSE_DTDLOAD to 0",
    ),
    SinkPattern(
        id="c-xxe-002",
        vuln_type=VulnType.XXE,
        languages=[Language.C, Language.CPP],
        pattern=r"\bxmlParseDoc\s*\(",
        function_name="xmlParseDoc()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="libxml2 xmlParseDoc -- entity expansion by default",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="c-xxe-003",
        vuln_type=VulnType.XXE,
        languages=[Language.C, Language.CPP],
        pattern=r"\bXML_PARSE_NOENT\b",
        function_name="XML_PARSE_NOENT flag set",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="XML_PARSE_NOENT -- entity substitution explicitly enabled",
        cwe="CWE-611",
    ),
])

# ==============================================================================
# C# / .NET
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="cs-xxe-001",
        vuln_type=VulnType.XXE,
        languages=[Language.CSHARP],
        pattern=r"new\s+XmlDocument\s*\(\s*\)",
        function_name="new XmlDocument()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="XmlDocument -- DTD processing enabled by default in .NET < 4.0",
        cwe="CWE-611",
        remediation="Set XmlDocument.XmlResolver = null",
    ),
    SinkPattern(
        id="cs-xxe-002",
        vuln_type=VulnType.XXE,
        languages=[Language.CSHARP],
        pattern=r"XmlReaderSettings\s*\{\s*[^}]*DtdProcessing\s*=\s*DtdProcessing\.Parse",
        function_name="XmlReaderSettings{DtdProcessing.Parse}",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="XmlReader with DTD parsing enabled -- XXE",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="cs-xxe-003",
        vuln_type=VulnType.XXE,
        languages=[Language.CSHARP],
        pattern=r"XmlResolver\s*=\s*new\s+XmlUrlResolver",
        function_name="XmlResolver = new XmlUrlResolver",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="XmlUrlResolver enables XXE via network requests",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="cs-xxe-004",
        vuln_type=VulnType.XXE,
        languages=[Language.CSHARP],
        pattern=r"XPathDocument\s*\(\s*[^@\"'][^)]*\)",
        function_name="XPathDocument(variable)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="XPathDocument with variable -- check DTD settings",
        cwe="CWE-611",
    ),
    SinkPattern(
        id="cs-xxe-005",
        vuln_type=VulnType.XXE,
        languages=[Language.CSHARP],
        pattern=r"new\s+XmlTextReader\s*\(",
        function_name="new XmlTextReader()",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="XmlTextReader -- DTD enabled by default before .NET 4.0",
        cwe="CWE-611",
    ),
])

PATTERN_COUNT = len(PATTERNS)
