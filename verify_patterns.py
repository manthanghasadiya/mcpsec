from mcpsec.static.patterns.registry import PatternRegistry
stats = PatternRegistry.get().stats()
print("Registry loaded OK")
print(f"Total sinks: {stats['total_sink_patterns']}")
print(f"Total sources: {stats['total_source_patterns']}")
print(f"Total sanitizers: {stats['total_sanitizer_patterns']}")
print("By language:", stats["by_language"])
print("By vuln type:", stats["by_vuln_type"])
assert stats["total_sink_patterns"] >= 800, f"Need 800+ patterns, got {stats['total_sink_patterns']}"
print("PATTERN COUNT OK")
