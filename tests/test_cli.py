"""_resolve_mode: the pure decision logic behind --mode pentest, tested
without touching argparse or the agent loop."""

from d3m0n.agent.prompts import PENTEST_MODE_DIRECTIVE, PENTEST_MODE_MIN_STEPS
from d3m0n.cli import _resolve_mode


def test_default_mode_passes_through_unchanged():
    directive, steps, critic = _resolve_mode("default", 25, 25)
    assert directive is None
    assert steps == 25
    assert critic is False


def test_pentest_mode_bumps_untouched_default():
    directive, steps, critic = _resolve_mode("pentest", 25, 25)
    assert directive == PENTEST_MODE_DIRECTIVE
    assert steps == PENTEST_MODE_MIN_STEPS
    assert critic is True


def test_pentest_mode_respects_explicit_higher_value():
    _, steps, _ = _resolve_mode("pentest", 100, 25)
    assert steps == 100


def test_pentest_mode_respects_explicit_lower_value():
    # An explicit choice, even a deliberately small one, is never
    # second-guessed -- only the untouched default gets raised.
    _, steps, _ = _resolve_mode("pentest", 5, 25)
    assert steps == 5


def test_pentest_mode_default_already_at_or_above_floor():
    _, steps, _ = _resolve_mode("pentest", 80, 80)
    assert steps == 80
