from mcpsec.scanners.prompt_injection import PromptInjectionScanner
from mcpsec.scanners.auth_audit import AuthAuditScanner
from mcpsec.scanners.path_traversal import PathTraversalScanner
from mcpsec.scanners.command_injection import CommandInjectionScanner
from mcpsec.scanners.ssrf import SSRFScanner
from mcpsec.scanners.description_prompt_injection import DescriptionPromptInjectionScanner
from mcpsec.scanners.resource_ssrf import ResourceSSRFScanner
from mcpsec.scanners.capability_escalation import CapabilityEscalationScanner
from .sql_rce import SQLInjectionRCEScanner

__all__ = [
    "PromptInjectionScanner",
    "AuthAuditScanner",
    "PathTraversalScanner",
    "CommandInjectionScanner",
    "SSRFScanner",
    "DescriptionPromptInjectionScanner",
    "ResourceSSRFScanner",
    "CapabilityEscalationScanner",
    "SQLInjectionRCEScanner",
]

SCANNERS = {
    "prompt-injection": PromptInjectionScanner,
    "auth-audit": AuthAuditScanner,
    "path-traversal": PathTraversalScanner,
    "command-injection": CommandInjectionScanner,
    "ssrf": SSRFScanner,
    "description-prompt-injection": DescriptionPromptInjectionScanner,
    "resource-ssrf": ResourceSSRFScanner,
    "capability-escalation": CapabilityEscalationScanner,
    "sql-rce": SQLInjectionRCEScanner,
}
