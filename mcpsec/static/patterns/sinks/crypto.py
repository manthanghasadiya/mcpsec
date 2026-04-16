"""
Cryptographic weakness patterns -- ~80 patterns.

Coverage:
- Weak algorithms: MD5, SHA1, DES, RC4, ECB mode
- Hardcoded keys, IVs, secrets, passwords
- Insecure random number generation
- Weak TLS/SSL configuration
- JWT algorithm confusion (alg:none)
"""

from mcpsec.static.patterns.base import (
    SinkPattern, Language, VulnType, Severity, Confidence
)

PATTERNS: list[SinkPattern] = []

# ==============================================================================
# WEAK HASH ALGORITHMS -- across all languages
# ==============================================================================

# TypeScript / JavaScript
PATTERNS.extend([
    SinkPattern(
        id="js-crypto-001",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"createHash\s*\(\s*['\"]md5['\"]",
        function_name="createHash('md5')",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="MD5 hash -- cryptographically broken",
        cwe="CWE-327",
        remediation="Use SHA-256 or SHA-3 for integrity. Use bcrypt/argon2 for passwords.",
    ),
    SinkPattern(
        id="js-crypto-002",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"createHash\s*\(\s*['\"]sha1['\"]",
        function_name="createHash('sha1')",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="SHA1 hash -- deprecated, collision attacks known",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="js-crypto-003",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"createCipheriv\s*\(\s*['\"](?:des|rc2|rc4|blowfish)['\"]",
        function_name="createCipheriv('des/rc4')",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Broken cipher algorithm (DES/RC4/RC2/Blowfish)",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="js-crypto-004",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"createCipheriv\s*\(\s*['\"]aes-\d+-ecb['\"]",
        function_name="createCipheriv('aes-XXX-ecb')",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="AES in ECB mode -- deterministic, patterns visible",
        cwe="CWE-327",
        remediation="Use AES-GCM or AES-CBC with random IV",
    ),
    SinkPattern(
        id="js-crypto-005",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"\bMath\.random\s*\(\s*\)",
        function_name="Math.random()",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="Math.random() -- not cryptographically secure",
        cwe="CWE-338",
        remediation="Use crypto.getRandomValues() or crypto.randomBytes()",
    ),
    SinkPattern(
        id="js-crypto-006",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"crypto\.createHash\s*\(\s*['\"]md4['\"]",
        function_name="createHash('md4')",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="MD4 hash -- extremely weak",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="js-crypto-007",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"process\.env\.\w+\s*\|\|\s*['\"][a-zA-Z0-9+/=_\-]{16,}['\"]",
        function_name="process.env.SECRET || 'hardcoded'",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Hardcoded secret fallback -- insecure default",
        cwe="CWE-798",
    ),
])

# Python
PATTERNS.extend([
    SinkPattern(
        id="py-crypto-001",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"\bhashlib\.md5\s*\(",
        function_name="hashlib.md5()",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="MD5 hash -- cryptographically broken",
        cwe="CWE-327",
        remediation="Use hashlib.sha256() or hashlib.sha3_256()",
    ),
    SinkPattern(
        id="py-crypto-002",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"\bhashlib\.sha1\s*\(",
        function_name="hashlib.sha1()",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="SHA1 hash -- deprecated for security use",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="py-crypto-003",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"\bDES\b|\bDES3\b|\bARC4\b|\bBlowfish\b",
        function_name="DES/DES3/RC4/Blowfish",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Broken cipher (DES/RC4/Blowfish) from pycryptodome",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="py-crypto-004",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"AES\.MODE_ECB",
        function_name="AES.MODE_ECB",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="AES in ECB mode -- deterministic encryption",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="py-crypto-005",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"\brandom\.(?:random|randint|choice|seed)\s*\(",
        function_name="random.random()",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="Python random module -- not cryptographically secure",
        cwe="CWE-338",
        remediation="Use secrets module or os.urandom() for security purposes",
    ),
    SinkPattern(
        id="py-crypto-006",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"\bos\.urandom\s*\(\s*[1-9]\b",
        function_name="os.urandom(small_n)",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="os.urandom() with too few bytes -- insufficient entropy",
        cwe="CWE-331",
    ),
    SinkPattern(
        id="py-crypto-007",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"\bRSA\.generate\s*\(\s*(?:512|768|1024)\b",
        function_name="RSA.generate(< 2048)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="RSA key size < 2048 bits -- factoring attacks feasible",
        cwe="CWE-326",
    ),
])

# Go
PATTERNS.extend([
    SinkPattern(
        id="go-crypto-001",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.GO],
        pattern=r"\bmd5\.New\s*\(\s*\)",
        function_name="md5.New()",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="MD5 hash usage",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="go-crypto-002",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.GO],
        pattern=r"\bsha1\.New\s*\(\s*\)",
        function_name="sha1.New()",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="SHA1 hash usage",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="go-crypto-003",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.GO],
        pattern=r"\bdes\.NewCipher\s*\(",
        function_name="des.NewCipher()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="DES cipher -- cryptographically broken",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="go-crypto-004",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.GO],
        pattern=r"\brc4\.NewCipher\s*\(",
        function_name="rc4.NewCipher()",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="RC4 cipher -- broken",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="go-crypto-005",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.GO],
        pattern=r"\bcipher\.NewECBEncrypter\b|\bNewECBDecrypter\b",
        function_name="ECB mode cipher",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="ECB mode cipher -- non-standard Go, look for third-party",
        cwe="CWE-327",
    ),
    SinkPattern(
        id="go-crypto-006",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.GO],
        pattern=r"\bmath/rand\b",
        function_name="math/rand",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="math/rand import -- not cryptographically secure",
        cwe="CWE-338",
        remediation="Use crypto/rand for security-sensitive operations",
    ),
    SinkPattern(
        id="go-crypto-007",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.GO],
        pattern=r"InsecureSkipVerify\s*:\s*true",
        function_name="InsecureSkipVerify: true",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="TLS certificate verification disabled",
        cwe="CWE-295",
    ),
])

# ==============================================================================
# HARDCODED SECRETS -- across languages
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="all-crypto-hc-001",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT, Language.PYTHON, Language.GO, Language.RUST],
        pattern=r"(?i)(?:password|passwd|secret|api_key|apikey|private_key|access_token|auth_token)\s*[=:]\s*['\"][a-zA-Z0-9!@#$%^&*_\-+=]{12,}['\"]",
        function_name="hardcoded credential",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        description="Hardcoded credential/secret value",
        cwe="CWE-798",
        remediation="Use environment variables or a secrets manager",
        negative_patterns=[
            r"(?i)example|placeholder|changeme|your_|my_|insert|REPLACE",
            r"(?i)test|spec|dummy|fake|mock",
        ],
    ),
    SinkPattern(
        id="all-crypto-hc-002",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT, Language.PYTHON, Language.GO],
        pattern=r"(?i)jwt.*secret.*=.*['\"][a-zA-Z0-9_\-]{10,}['\"]",
        function_name="hardcoded JWT secret",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Hardcoded JWT signing secret",
        cwe="CWE-798",
    ),
])

# ==============================================================================
# JWT weaknesses
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="js-jwt-001",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"jwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*none",
        function_name="jwt.verify(algorithms:[none])",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="JWT verify allows 'none' algorithm -- algorithm confusion",
        cwe="CWE-327",
        tags=["jwt"],
    ),
    SinkPattern(
        id="js-jwt-002",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"jwt\.decode\s*\([^)]*(?!verify)[^)]*\)",
        function_name="jwt.decode() without verify",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="jwt.decode without signature verification -- trust but don't verify",
        cwe="CWE-347",
        negative_patterns=[r"jwt\.verify"],
    ),
    SinkPattern(
        id="py-jwt-001",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify_signature\s*:\s*False",
        function_name="jwt.decode(verify_signature=False)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="PyJWT decode with signature verification disabled",
        cwe="CWE-347",
    ),
    SinkPattern(
        id="py-jwt-002",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"jwt\.decode\s*\([^)]*algorithms\s*=\s*\[[^\]]*none",
        function_name="jwt.decode(algorithms=['none'])",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="PyJWT allows 'none' algorithm",
        cwe="CWE-327",
    ),
])

# ==============================================================================
# WEAK TLS / SSL
# ==============================================================================

PATTERNS.extend([
    SinkPattern(
        id="py-tls-001",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"ssl\.PROTOCOL_SSLv2\b|ssl\.PROTOCOL_SSLv3\b|ssl\.PROTOCOL_TLSv1\b",
        function_name="ssl.PROTOCOL_SSLv2/3/TLSv1",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Deprecated SSL/TLS protocol version",
        cwe="CWE-326",
        remediation="Use ssl.PROTOCOL_TLS_CLIENT with ssl.TLSVersion.TLSv1_2 minimum",
    ),
    SinkPattern(
        id="py-tls-002",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.PYTHON],
        pattern=r"verify\s*=\s*False",
        function_name="verify=False",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        description="TLS verification disabled in requests/httpx",
        cwe="CWE-295",
        context_patterns=[r"requests\.|httpx\."],
    ),
    SinkPattern(
        id="js-tls-001",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"rejectUnauthorized\s*:\s*false",
        function_name="rejectUnauthorized: false",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="TLS certificate validation disabled in Node.js HTTPS",
        cwe="CWE-295",
    ),
    SinkPattern(
        id="js-tls-002",
        vuln_type=VulnType.CRYPTO,
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        pattern=r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]",
        function_name="NODE_TLS_REJECT_UNAUTHORIZED=0",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="TLS verification disabled via environment variable",
        cwe="CWE-295",
    ),
])

PATTERN_COUNT = len(PATTERNS)
