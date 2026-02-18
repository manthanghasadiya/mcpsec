"""
JSON Reporter — generates structured JSON reports of scan results.
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

from mcpsec.models import ScanResult

def generate_json_report(result: ScanResult, output_path: str) -> bool:
    """
    Generate a detailed JSON report from a ScanResult.
    
    Args:
        result: The ScanResult object containing all findings
        output_path: Path to write the JSON file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # result.to_json() uses pydantic's model_dump_json
        # which already handles nested models and datetime serialization
        report_data = result.model_dump(mode="json")
        
        # Add some extra reporter-specific metadata if needed
        report_data["report_generated_at"] = datetime.now(timezone.utc).isoformat()
        report_data["version"] = "0.1.0" # Should match package version
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
            
        return True
    except Exception:
        # Higher level logic should handle the error/logging
        return False
