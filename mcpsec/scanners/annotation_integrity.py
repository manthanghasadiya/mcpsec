"""Scanner for MCP tool annotation integrity."""

from mcpsec.models import Finding, Severity

SCANNER_NAME = "annotation-integrity"

WRITE_VERBS = {"create", "update", "delete", "modify", "write", "insert", 
               "patch", "put", "post", "send", "push", "add", "set", "remove"}
               
DESTRUCTIVE_VERBS = {"delete", "remove", "drop", "truncate", "destroy", 
                      "purge", "wipe", "clear", "reset", "kill", "terminate"}

WRITE_PARAMS = {"content", "body", "data", "payload", "text", "message",
                "value", "input", "file", "document"}

def scan_annotations(tools: list) -> list[Finding]:
    findings = []
    
    for tool in tools:
        name = tool.name or ""
        desc = (tool.description or "").lower()
        annotations = tool.annotations or {}
        param_names = set()
        
        # Extract parameter names
        if tool.raw_schema:
             props = tool.raw_schema.get("properties", {})
             param_names = {p.lower() for p in props.keys()}
        elif tool.parameters:
             # Fallback to parameters dict keys if raw_schema is empty
             param_names = {p.lower() for p in tool.parameters.keys()}
        
        # Check: No annotations at all
        if not annotations:
            findings.append(Finding(
                severity=Severity.LOW,
                scanner=SCANNER_NAME,
                tool_name=name,
                title="Missing Tool Annotations",
                description=f"Tool '{name}' has no behavior annotations (readOnlyHint, destructiveHint, etc.). Clients cannot make informed decisions about tool safety.",
                remediation="Add appropriate MCP annotations to declare tool behavior.",
            ))
            continue
        
        read_only = annotations.get("readOnlyHint", False)
        destructive = annotations.get("destructiveHint", False)
        
        # Check: Claims read-only but has write indicators
        if read_only:
            name_lower = name.lower().replace("_", " ").replace("-", " ")
            name_words = set(name_lower.split())
            desc_words = set(desc.split())
            
            write_in_name = name_words & WRITE_VERBS
            write_in_desc = desc_words & WRITE_VERBS  
            write_in_params = param_names & WRITE_PARAMS
            
            indicators = []
            if write_in_name:
                indicators.append(f"name contains: {', '.join(write_in_name)}")
            if write_in_desc:
                indicators.append(f"description contains: {', '.join(list(write_in_desc)[:3])}")
            if write_in_params:
                indicators.append(f"parameters include: {', '.join(write_in_params)}")
            
            if indicators:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    scanner=SCANNER_NAME,
                    tool_name=name,
                    title="Annotation Mismatch: Claims Read-Only But Has Write Indicators",
                    description=f"Tool '{name}' has readOnlyHint=true but shows write behavior: {'; '.join(indicators)}",
                    evidence=f"Annotations: {annotations}",
                    remediation="Either set readOnlyHint=false or remove write functionality.",
                ))
        
        # Check: Has destructive behavior but no destructiveHint
        if not destructive:
            name_words = set(name.lower().replace("_", " ").replace("-", " ").split())
            destructive_in_name = name_words & DESTRUCTIVE_VERBS
            destructive_in_desc = set(desc.split()) & DESTRUCTIVE_VERBS
            
            if destructive_in_name or destructive_in_desc:
                indicators = []
                if destructive_in_name:
                    indicators.append(f"name: {', '.join(destructive_in_name)}")
                if destructive_in_desc:
                    indicators.append(f"description: {', '.join(list(destructive_in_desc)[:3])}")
                    
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    scanner=SCANNER_NAME,
                    tool_name=name,
                    title="Missing Destructive Hint on Potentially Destructive Tool",
                    description=f"Tool '{name}' appears destructive ({'; '.join(indicators)}) but has no destructiveHint annotation.",
                    remediation="Add destructiveHint=true to warn clients about destructive behavior.",
                ))
    
    return findings
