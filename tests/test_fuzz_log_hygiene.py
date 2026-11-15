"""Tests verifying fuzz log hygiene: logs must never land in cwd and must truncate per run."""

import os
import re
import sys
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from mcpsec.cli import app
from mcpsec.fuzzer.fuzz_engine import FuzzEngine
from mcpsec.fuzzer.transport.stdio_fuzzer import StdioFuzzer


def test_default_error_log_path_under_tempdir():
    """Constructing StdioFuzzer with no explicit path puts log in system temp directory."""
    fuzzer = StdioFuzzer("dummy")
    log_path = Path(fuzzer.error_log_path)
    temp_dir = Path(tempfile.gettempdir())

    assert log_path.parent.resolve() == temp_dir.resolve()
    assert f"mcpsec_fuzz_{os.getpid()}.log" in log_path.name
    assert not os.path.exists("mcpsec_fuzz_stderr.log")


def test_explicit_error_log_path_override(tmp_path):
    """Explicit error_log_path override is honored by StdioFuzzer."""
    custom_log = str(tmp_path / "custom_stderr.log")
    fuzzer = StdioFuzzer("dummy", error_log_path=custom_log)
    assert fuzzer.error_log_path == custom_log


def test_error_log_opened_truncating(tmp_path):
    """Log file is opened in write/truncate mode so prior run contents do not persist."""
    log_file = tmp_path / "fuzz.log"
    log_file.write_text("prior run output from previous campaign\n", encoding="utf-8")
    assert "prior run" in log_file.read_text(encoding="utf-8")

    cmd = f'"{sys.executable}" -V'
    fuzzer = StdioFuzzer(cmd, error_log_path=str(log_file))
    fuzzer.start_server()
    fuzzer.stop_server()

    contents = log_file.read_text(encoding="utf-8")
    assert "prior run output from previous campaign" not in contents


def test_cwd_cleanliness_after_default_run():
    """Running fuzzer with default log path creates no file in the current working directory."""
    cwd_log = os.path.join(os.getcwd(), "mcpsec_fuzz_stderr.log")
    assert not os.path.exists(cwd_log)

    cmd = f'"{sys.executable}" -V'
    fuzzer = StdioFuzzer(cmd)
    fuzzer.start_server()
    fuzzer.stop_server()

    assert not os.path.exists(cwd_log)
    # Ensure no mcpsec_fuzz_*.log in cwd
    cwd_files = [f for f in os.listdir(".") if f.startswith("mcpsec_fuzz_") and f.endswith(".log")]
    assert len(cwd_files) == 0


def test_fuzz_engine_threads_fuzz_log(tmp_path):
    """FuzzEngine accepts and threads the fuzz_log argument."""
    custom_log = str(tmp_path / "engine_stderr.log")
    engine = FuzzEngine("dummy", fuzz_log=custom_log)
    assert engine.fuzz_log == custom_log

    engine_default = FuzzEngine("dummy")
    assert engine_default.fuzz_log is None


def test_cli_fuzz_log_option():
    """The fuzz CLI command exposes the --fuzz-log option."""
    runner = CliRunner()
    result = runner.invoke(app, ["fuzz", "--help"])
    assert result.exit_code == 0
    clean_output = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", result.output)
    assert "--fuzz-log" in clean_output
