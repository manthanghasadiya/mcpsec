"""
Framework detection -- identify which MCP SDK/framework is used.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import re
from typing import Optional


class Language(str, Enum):
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"
    PYTHON = "python"
    GO = "go"
    RUST = "rust"
    C = "c"
    CSHARP = "csharp"
    UNKNOWN = "unknown"


class Framework(str, Enum):
    MCP_TS_SDK = "mcp-typescript-sdk"
    MCP_PY_SDK = "mcp-python-sdk"
    FASTMCP = "fastmcp"
    MCP_GO_SDK = "mcp-go-sdk"
    MCP_RUST_SDK = "mcp-rust-sdk"
    MCP_DOTNET = "mcp-dotnet"
    MCP_C_CUSTOM = "mcp-c-custom"
    UNKNOWN = "unknown"


@dataclass
class FrameworkInfo:
    """Detected framework information."""
    language: Language
    framework: Framework
    extensions: list[str]
    confidence: float = 1.0


# Detection signatures
FRAMEWORK_SIGNATURES: dict[Framework, dict] = {
    Framework.MCP_TS_SDK: {
        "package_json": ["@modelcontextprotocol/sdk", "@anthropic/mcp"],
        "code_patterns": [
            r"server\.tool\s*\(",
            r"McpServer",
            r"CallToolRequestSchema",
        ],
    },
    Framework.MCP_PY_SDK: {
        "requirements": ["mcp>=", "mcp==", "mcp["],
        "code_patterns": [
            r"@mcp\.tool",
            r"from\s+mcp\s+import",
            r"from\s+mcp\.server",
        ],
    },
    Framework.FASTMCP: {
        "requirements": ["fastmcp"],
        "code_patterns": [
            r"from\s+fastmcp\s+import",
            r"FastMCP\s*\(",
        ],
    },
    Framework.MCP_GO_SDK: {
        "go_mod": ["github.com/mark3labs/mcp-go"],
        "code_patterns": [
            r"mcp\.NewServer",
            r"RegisterTool",
        ],
    },
    Framework.MCP_RUST_SDK: {
        "cargo_toml": ["mcp-server", "mcp-rs"],
        "code_patterns": [
            r"#\[tool\]",
            r"impl\s+Tool",
        ],
    },
    Framework.MCP_C_CUSTOM: {
        "code_patterns": [
            r"json_object_get",
            r"r2_mcp\|r2pipe",
            r"\"jsonrpc\"",
        ],
    },
}


_LANG_EXTENSIONS: dict[Language, list[str]] = {
    Language.TYPESCRIPT: [".ts", ".tsx", ".js", ".jsx", ".mjs"],
    Language.JAVASCRIPT: [".js", ".jsx", ".mjs", ".cjs"],
    Language.PYTHON: [".py"],
    Language.GO: [".go"],
    Language.RUST: [".rs"],
    Language.C: [".c", ".h"],
    Language.CSHARP: [".cs"],
}


def detect_framework(project_path: Path) -> FrameworkInfo:
    """
    Detect the MCP framework used in a project.
    """
    language = _detect_language(project_path)
    framework = _detect_framework(project_path, language)

    extensions = _LANG_EXTENSIONS.get(language, [".ts", ".js", ".py"])

    return FrameworkInfo(
        language=language,
        framework=framework,
        extensions=extensions,
    )


def _detect_language(project_path: Path) -> Language:
    """Detect primary language from project files."""
    if not project_path.is_dir():
        # Single file -- detect from extension
        ext = project_path.suffix.lower()
        for lang, exts in _LANG_EXTENSIONS.items():
            if ext in exts:
                return lang
        return Language.UNKNOWN

    # Check config files first (most reliable)
    if (project_path / "package.json").exists():
        # Could be TS or JS -- check for tsconfig
        if (project_path / "tsconfig.json").exists():
            return Language.TYPESCRIPT
        return Language.JAVASCRIPT
    if (project_path / "go.mod").exists():
        return Language.GO
    if (project_path / "Cargo.toml").exists():
        return Language.RUST
    if any(
        (project_path / f).exists()
        for f in ["requirements.txt", "pyproject.toml", "setup.py", "setup.cfg"]
    ):
        return Language.PYTHON
    if any(project_path.rglob("*.csproj")):
        return Language.CSHARP

    # Count files by extension
    counts: dict[Language, int] = {
        Language.PYTHON: len(list(project_path.rglob("*.py"))),
        Language.TYPESCRIPT: (
            len(list(project_path.rglob("*.ts")))
            + len(list(project_path.rglob("*.tsx")))
        ),
        Language.JAVASCRIPT: (
            len(list(project_path.rglob("*.js")))
            + len(list(project_path.rglob("*.jsx")))
        ),
        Language.GO: len(list(project_path.rglob("*.go"))),
        Language.C: (
            len(list(project_path.rglob("*.c")))
            + len(list(project_path.rglob("*.h")))
        ),
        Language.RUST: len(list(project_path.rglob("*.rs"))),
    }

    # Exclude zero counts
    non_zero = {k: v for k, v in counts.items() if v > 0}
    if non_zero:
        return max(non_zero, key=lambda k: non_zero[k])

    return Language.UNKNOWN


def _detect_framework(project_path: Path, language: Language) -> Framework:
    """Detect specific MCP framework."""
    _path = project_path if project_path.is_dir() else project_path.parent

    # Check package.json
    pkg_json = _path / "package.json"
    if pkg_json.exists():
        try:
            content = pkg_json.read_text(encoding="utf-8", errors="ignore")
            for fw, sigs in FRAMEWORK_SIGNATURES.items():
                for pkg in sigs.get("package_json", []):
                    if pkg in content:
                        return fw
        except Exception:
            pass

    # Check requirements.txt / pyproject.toml
    for req_file in ["requirements.txt", "pyproject.toml"]:
        req_path = _path / req_file
        if req_path.exists():
            try:
                content = req_path.read_text(encoding="utf-8", errors="ignore")
                for fw, sigs in FRAMEWORK_SIGNATURES.items():
                    for req in sigs.get("requirements", []):
                        if req in content:
                            return fw
            except Exception:
                pass

    # Check go.mod
    go_mod = _path / "go.mod"
    if go_mod.exists():
        try:
            content = go_mod.read_text(encoding="utf-8", errors="ignore")
            for fw, sigs in FRAMEWORK_SIGNATURES.items():
                for mod in sigs.get("go_mod", []):
                    if mod in content:
                        return fw
        except Exception:
            pass

    # Check Cargo.toml
    cargo_toml = _path / "Cargo.toml"
    if cargo_toml.exists():
        try:
            content = cargo_toml.read_text(encoding="utf-8", errors="ignore")
            for fw, sigs in FRAMEWORK_SIGNATURES.items():
                for dep in sigs.get("cargo_toml", []):
                    if dep in content:
                        return fw
        except Exception:
            pass

    # Fall back to code pattern matching (scan a few files)
    _root = _path if _path.is_dir() else _path.parent
    scanned = 0
    for ext in [".ts", ".js", ".py", ".go", ".rs", ".c"]:
        for fp in _root.rglob(f"*{ext}"):
            if _is_excluded(fp) or scanned > 20:
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
                for fw, sigs in FRAMEWORK_SIGNATURES.items():
                    for pattern in sigs.get("code_patterns", []):
                        if re.search(pattern, content):
                            return fw
                scanned += 1
            except Exception:
                continue

    return Framework.UNKNOWN


def _is_excluded(path: Path) -> bool:
    """Check if path should be excluded."""
    exclude = [
        "node_modules", "dist", "build", ".git",
        "__pycache__", "venv", ".venv", "vendor",
    ]
    path_str = str(path)
    return any(f"/{ex}/" in path_str or f"\\{ex}\\" in path_str for ex in exclude)


def _map_language(lang: Language):
    """Map detector Language to patterns base Language for cross-module use."""
    from mcpsec.static.patterns.base import Language as PatternLanguage
    mapping = {
        Language.TYPESCRIPT: PatternLanguage.TYPESCRIPT,
        Language.JAVASCRIPT: PatternLanguage.JAVASCRIPT,
        Language.PYTHON: PatternLanguage.PYTHON,
        Language.GO: PatternLanguage.GO,
        Language.RUST: PatternLanguage.RUST,
        Language.C: PatternLanguage.C,
        Language.CSHARP: PatternLanguage.CSHARP,
    }
    return mapping.get(lang)
