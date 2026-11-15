from pathlib import Path

from mcpsec.fuzzer.transport.stdio_fuzzer import StdioFuzzer


class FakeProcess:
    def __init__(self, returncode: int | None):
        self._returncode = returncode

    def poll(self) -> int | None:
        return self._returncode


def test_fuzz_signal_crash_linux_macos(tmp_path: Path):
    empty_log = tmp_path / "empty_stderr.log"
    empty_log.write_text("")

    fuzzer = StdioFuzzer(command="dummy_server", error_log_path=str(empty_log))

    # SIGSEGV (-11)
    fuzzer.process = FakeProcess(-11)
    is_crash, reason = fuzzer._check_real_crash()
    assert is_crash is True
    assert reason == "signal_11"

    # SIGABRT (-6)
    fuzzer.process = FakeProcess(-6)
    is_crash, reason = fuzzer._check_real_crash()
    assert is_crash is True
    assert reason == "signal_6"

    # Graceful exit (0)
    fuzzer.process = FakeProcess(0)
    is_crash, reason = fuzzer._check_real_crash()
    assert is_crash is False
    assert reason == "graceful_exit"

    # Non-zero exit code 1 with empty stderr -> handled_error
    fuzzer.process = FakeProcess(1)
    is_crash, reason = fuzzer._check_real_crash()
    assert is_crash is False
    assert reason == "handled_error"
