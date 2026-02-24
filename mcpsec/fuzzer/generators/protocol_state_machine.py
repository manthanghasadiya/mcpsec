"""
Protocol State Machine Fuzzer for MCP.

Tests what happens when:
1. Methods called before initialize
2. Double initialize
3. Wrong protocol versions
4. Methods after shutdown
5. Missing required fields in initialize
"""

from typing import Any

# Generator metadata
GENERATOR_NAME = "protocol_state_machine"
GENERATOR_DESCRIPTION = "Tests MCP protocol state machine violations"
CATEGORY = "protocol"
INTENSITY_LEVELS = {
    "low": 10,
    "medium": 25,
    "high": 50,
    "insane": 50
}


def generate(intensity: str = "medium") -> list[dict[str, Any]]:
    """Generate protocol state machine violation test cases."""
    cases = []
    max_cases = INTENSITY_LEVELS.get(intensity, 25)
    
    # ===========================================
    # Category 1: Methods before initialize
    # ===========================================
    pre_init_methods = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "test", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
        {"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "file:///etc/passwd"}},
        {"jsonrpc": "2.0", "id": 5, "method": "prompts/list", "params": {}},
        {"jsonrpc": "2.0", "id": 6, "method": "prompts/get", "params": {"name": "test"}},
        {"jsonrpc": "2.0", "id": 7, "method": "completion/complete", "params": {"ref": {"type": "ref/prompt", "name": "test"}, "argument": {"name": "arg", "value": "val"}}},
        {"jsonrpc": "2.0", "id": 8, "method": "logging/setLevel", "params": {"level": "debug"}},
        {"jsonrpc": "2.0", "id": 9, "method": "sampling/createMessage", "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "test"}}], "maxTokens": 100}},
    ]
    
    for msg in pre_init_methods:
        cases.append({
            "name": f"pre_init_{msg['method'].replace('/', '_')}",
            "description": f"Call {msg['method']} before initialize - should fail gracefully",
            "payload": msg,
            "expects_error": True,
            "crash_indicates_bug": True,
            "skip_init": True,  # Special flag: don't send initialize first
        })
    
    # ===========================================
    # Category 2: Double/Multiple Initialize
    # ===========================================
    cases.append({
        "name": "double_initialize",
        "description": "Send initialize twice - should reject second or handle gracefully",
        "payload": {"jsonrpc": "2.0", "id": 100, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcpsec-fuzzer", "version": "1.0.0"}
        }},
        "expects_error": True,
        "crash_indicates_bug": True,
        "send_after_init": True,  # Send AFTER normal init sequence
    })
    
    cases.append({
        "name": "triple_initialize",
        "description": "Send initialize three times rapidly",
        "payload": {"jsonrpc": "2.0", "id": 101, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcpsec-fuzzer", "version": "1.0.0"}
        }},
        "expects_error": True,
        "crash_indicates_bug": True,
        "repeat": 3,
        "skip_init": True,
    })
    
    # ===========================================
    # Category 3: Wrong Protocol Versions
    # ===========================================
    bad_versions = [
        ("future_version", "9999.99.99", "Far future version"),
        ("ancient_version", "0.0.1", "Ancient version"),
        ("empty_version", "", "Empty version string"),
        ("null_version", None, "Null version"),
        ("numeric_version", 2024, "Numeric instead of string"),
        ("array_version", ["2024-11-05"], "Array instead of string"),
        ("object_version", {"version": "2024-11-05"}, "Object instead of string"),
        ("negative_version", "-1.0.0", "Negative version"),
        ("special_chars", "2024-11-05; DROP TABLE", "SQL injection in version"),
        ("unicode_version", "2024-11-05\u0000hidden", "Null byte in version"),
        ("long_version", "A" * 10000, "Extremely long version string"),
    ]
    
    for name, version, desc in bad_versions:
        params = {
            "capabilities": {},
            "clientInfo": {"name": "mcpsec-fuzzer", "version": "1.0.0"}
        }
        if version is not None:
            params["protocolVersion"] = version
        # else: missing protocolVersion entirely
        
        cases.append({
            "name": f"bad_version_{name}",
            "description": desc,
            "payload": {"jsonrpc": "2.0", "id": 200, "method": "initialize", "params": params},
            "expects_error": True,
            "crash_indicates_bug": True,
            "skip_init": True,
        })
    
    # ===========================================
    # Category 4: Malformed Initialize Params
    # ===========================================
    malformed_inits = [
        ("no_params", None, "Initialize with no params"),
        ("empty_params", {}, "Initialize with empty params"),
        ("null_capabilities", {"protocolVersion": "2024-11-05", "capabilities": None}, "Null capabilities"),
        ("string_capabilities", {"protocolVersion": "2024-11-05", "capabilities": "none"}, "String capabilities"),
        ("array_capabilities", {"protocolVersion": "2024-11-05", "capabilities": []}, "Array capabilities"),
        ("no_client_info", {"protocolVersion": "2024-11-05", "capabilities": {}}, "Missing clientInfo"),
        ("null_client_info", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": None}, "Null clientInfo"),
        ("empty_client_info", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {}}, "Empty clientInfo"),
        ("extra_fields", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}, "__proto__": {"admin": True}}, "Prototype pollution attempt"),
    ]
    
    for name, params, desc in malformed_inits:
        msg = {"jsonrpc": "2.0", "id": 300, "method": "initialize"}
        if params is not None:
            msg["params"] = params
        
        cases.append({
            "name": f"malformed_init_{name}",
            "description": desc,
            "payload": msg,
            "expects_error": True,
            "crash_indicates_bug": True,
            "skip_init": True,
        })
    
    # ===========================================
    # Category 5: Notifications Abuse
    # ===========================================
    notification_cases = [
        # initialized notification before initialize request
        ("premature_initialized", {"jsonrpc": "2.0", "method": "notifications/initialized"}, "Send initialized notification before initialize request", True),
        # initialized with ID (should be notification, no ID)
        ("initialized_with_id", {"jsonrpc": "2.0", "id": 400, "method": "notifications/initialized"}, "initialized notification with ID (invalid)", False),
        # Double initialized notification
        ("double_initialized", {"jsonrpc": "2.0", "method": "notifications/initialized"}, "Send initialized notification twice", False),
        # cancelled notification for non-existent request
        ("cancel_nonexistent", {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99999}}, "Cancel non-existent request", False),
        # progress notification for non-existent request
        ("progress_nonexistent", {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "fake", "progress": 50}}, "Progress for non-existent request", False),
    ]
    
    for name, payload, desc, skip_init in notification_cases:
        cases.append({
            "name": f"notification_{name}",
            "description": desc,
            "payload": payload,
            "expects_error": False,  # Notifications don't get responses
            "crash_indicates_bug": True,
            "skip_init": skip_init,
        })
    
    # ===========================================
    # Category 6: Shutdown/Exit Handling
    # ===========================================
    # Note: These test what happens AFTER shutdown
    post_shutdown_methods = ["tools/list", "resources/list", "prompts/list"]
    
    for method in post_shutdown_methods:
        cases.append({
            "name": f"post_shutdown_{method.replace('/', '_')}",
            "description": f"Call {method} after shutdown notification",
            "payload": {"jsonrpc": "2.0", "id": 500, "method": method, "params": {}},
            "expects_error": True,
            "crash_indicates_bug": True,
            "send_shutdown_first": True,
        })
    
    # Limit to intensity level
    return cases[:max_cases]
