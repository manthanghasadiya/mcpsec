# Recall Corpus Test Suite

This test suite provides a generic, data-driven test harness for regression testing `mcpsec` detection capabilities against real-world MCP server implementations.

## Architecture

The harness is divided into two layers:

1. **Committed generic harness (`tests/corpus/harness.py`, `tests/corpus/test_corpus.py`)**:
   Contains no target-specific server names, tool names, or vulnerability references. It exposes standard evaluation primitives for stdio lifecycle management, scanning, fuzzing, and recall assertion checking.
2. **Local target manifests (`tests/corpus/targets_local/`)**:
   Stores target configurations, stdio launch commands, and expected detection criteria. This directory is strictly gitignored to preserve privacy regarding specific test targets and vulnerability tracking.

## Manifest Schema

Target manifests are stored in `tests/corpus/targets_local/` as YAML or JSON files:

```yaml
ref: target-01
launch: "<stdio launch command for the built server>"
expect:
  - scanner: command-injection
    tool: target_tool
    confidence: confirmed
  - kind: fuzz-crash
    path: params
    real: true
```

## Running the Corpus Tests

When no local target manifests are present (for example, in continuous integration or on a fresh clone), the entire corpus test suite skips cleanly without errors:

```bash
pytest tests/corpus/ -v
```

When local targets are configured in `tests/corpus/targets_local/`:

```bash
pytest tests/corpus/ -v
```

## Philosophy on Detection Outcomes

The recall corpus measures detector coverage:
- **True Positives**: Confirm that existing scanners and oracles successfully catch target vulnerabilities.
- **Documented Misses**: When a known vulnerable condition is not flagged, that failure is an expected outcome and valuable diagnostic data that specifies requirements for the next detector, rather than a test to remove.
