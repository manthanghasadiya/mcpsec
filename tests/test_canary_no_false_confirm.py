import random
import re
import pytest

from mcpsec.scanners.oracles.command_injection import confirm_command_injection


@pytest.mark.asyncio
async def test_numeric_timestamp_or_id_never_falsely_confirms():
    """A fake call_fn that always returns fixed numeric output (timestamps/IDs) never confirms."""
    for seed in range(200):
        rng = random.Random(seed)
        static_id = str(rng.randint(100_000_000, 999_999_999))

        def call_fn(tool_name: str, args: dict):
            # Ignores payload and always returns a fixed response with a numeric ID
            return f"record id: {static_id}, status: ok\n", 0.01

        result = await confirm_command_injection(
            call_fn=call_fn,
            tool_name="test_tool",
            param_name="arg",
            base_args={"arg": "default"},
        )
        assert result.confirmed is False


@pytest.mark.asyncio
async def test_real_arithmetic_expansion_evaluates_and_confirms_twice():
    """A fake call_fn that evaluates arithmetic expansion confirms and names two evaluations."""

    def call_fn(tool_name: str, args: dict):
        val = str(args.get("arg", ""))

        def eval_posix(match):
            expr = match.group(1).replace(" ", "")
            a, b = expr.split("+")
            return str(int(a) + int(b))

        def eval_expr(match):
            a, b = match.group(1), match.group(2)
            return str(int(a) + int(b))

        executed = re.sub(r"\$\(\(\s*([^)]+?)\s*\)\)", eval_posix, val)
        executed = re.sub(r"`expr\s+(\d+)\s*\+\s*(\d+)`", eval_expr, executed)
        return f"Output: {executed}\n", 0.01

    result = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="cmd_tool",
        param_name="arg",
        base_args={"arg": "default"},
    )

    assert result.confirmed is True
    assert result.method == "canary"
    # Evidence must name both evaluations
    assert "confirmed twice:" in result.evidence
    # Matches two separate sum expressions: a+b=s and a2+b2=s2
    matches = re.findall(r"(\d+)\+(\d+)=(\d+)", result.evidence)
    assert len(matches) == 2
    for a, b, s in matches:
        assert int(a) + int(b) == int(s)


@pytest.mark.asyncio
async def test_baseline_already_containing_first_proof_does_not_confirm():
    """A fake call_fn whose baseline already contains the proof does not confirm."""
    # We will dynamically return whatever proof is being looked for on first call,
    # but the baseline response also contains that same proof.
    first_proof = [None]

    def call_fn(tool_name: str, args: dict):
        val = str(args.get("arg", ""))
        # Check if payload has arithmetic syntax
        m = re.search(r"\$\(\(\s*(\d+)\s*\+\s*(\d+)\s*\)\)", val)
        if m:
            if first_proof[0] is None:
                first_proof[0] = str(int(m.group(1)) + int(m.group(2)))
            # Only evaluate for the first proof; do not evaluate second pair
            if str(int(m.group(1)) + int(m.group(2))) == first_proof[0]:
                return f"Output: {first_proof[0]}\n", 0.01

        # If baseline or any other call, baseline contains the first proof
        if first_proof[0] is not None:
            return f"Baseline containing {first_proof[0]}", 0.01
        return "Baseline", 0.01

    result = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="cmd_tool",
        param_name="arg",
        base_args={"arg": "default"},
    )

    assert result.confirmed is False
