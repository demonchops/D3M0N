"""_resolve_mode: the pure decision logic behind --mode pentest, tested
without touching argparse or the agent loop. Also main()'s --engagement-
file wiring, with run_agent/write_report mocked so no real agent run or
network access happens."""

import d3m0n.cli as cli_mod
from d3m0n.agent.prompts import PENTEST_MODE_DIRECTIVE, PENTEST_MODE_MIN_STEPS
from d3m0n.cli import _resolve_mode, main


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


# --- main(): --engagement-file wiring ---


def _mock_agent_run(monkeypatch):
    captured = {}

    def fake_run_agent(objective, scope_raw, **kwargs):
        captured["objective"] = objective
        captured["scope_raw"] = scope_raw
        return {"findings": [], "summary": "done"}

    def fake_write_report(output_dir, objective, scope_raw, findings, **kwargs):
        captured["report_objective"] = objective
        return "/tmp/fake-report.json"

    monkeypatch.setattr(cli_mod, "run_agent", fake_run_agent)
    monkeypatch.setattr(cli_mod, "write_report", fake_write_report)
    return captured


def _write_engagement_json(tmp_path, **overrides):
    import json

    data = {
        "program": "Test",
        "scope": "example.com",
        "authorized": True,
        "confirmed_by": "tester",
        "objectives": [{"phase": "recon", "description": "enumerate subdomains"}],
    }
    data.update(overrides)
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(data))
    return str(path)


def test_engagement_file_supplies_objective_automatically(tmp_path, monkeypatch):
    captured = _mock_agent_run(monkeypatch)
    path = _write_engagement_json(tmp_path)

    exit_code = main(["--engagement-file", path])

    assert exit_code == 0
    assert "enumerate subdomains" in captured["objective"]
    assert captured["scope_raw"] == "example.com"


def test_engagement_file_plus_explicit_objective_appends(tmp_path, monkeypatch):
    captured = _mock_agent_run(monkeypatch)
    path = _write_engagement_json(tmp_path)

    main(["--engagement-file", path, "--objective", "also check CORS"])

    assert "enumerate subdomains" in captured["objective"]
    assert "also check CORS" in captured["objective"]


def test_engagement_file_not_authorized_exits_without_running(monkeypatch, tmp_path, capsys):
    captured = _mock_agent_run(monkeypatch)
    path = _write_engagement_json(tmp_path, authorized=False)

    exit_code = main(["--engagement-file", path])

    assert exit_code == 2
    assert "objective" not in captured
    assert "authorized" in capsys.readouterr().err


def test_engagement_file_no_objectives_and_no_flag_errors(monkeypatch, tmp_path, capsys):
    captured = _mock_agent_run(monkeypatch)
    path = _write_engagement_json(tmp_path, objectives=[])

    exit_code = main(["--engagement-file", path])

    assert exit_code == 2
    assert "objective" not in captured
    assert "nothing to work on" in capsys.readouterr().err


def test_engagement_file_no_objectives_but_explicit_objective_given(tmp_path, monkeypatch):
    captured = _mock_agent_run(monkeypatch)
    path = _write_engagement_json(tmp_path, objectives=[])

    exit_code = main(["--engagement-file", path, "--objective", "just this one thing"])

    assert exit_code == 0
    assert captured["objective"] == "just this one thing"


def test_engagement_yaml_file_also_works(tmp_path, monkeypatch):
    captured = _mock_agent_run(monkeypatch)
    path = tmp_path / "engagement.yaml"
    path.write_text(
        "scope: example.com\nauthorized: true\nconfirmed_by: tester\n"
        "objectives:\n  - phase: recon\n    description: enumerate subdomains\n"
    )

    exit_code = main(["--engagement-file", str(path)])

    assert exit_code == 0
    assert "enumerate subdomains" in captured["objective"]


def test_scope_file_without_objective_errors(monkeypatch, tmp_path, capsys):
    captured = _mock_agent_run(monkeypatch)
    path = tmp_path / "scope.json"
    path.write_text(
        '{"scope": "example.com", "authorized": true, "confirmed_by": "tester"}'
    )

    exit_code = main(["--scope-file", str(path)])

    assert exit_code == 2
    assert "objective" not in captured
    assert "--objective is required" in capsys.readouterr().err


def test_scope_without_objective_errors(monkeypatch, capsys):
    captured = _mock_agent_run(monkeypatch)
    monkeypatch.setattr(cli_mod, "confirm_authorization", lambda scope: None)

    exit_code = main(["--scope", "example.com"])

    assert exit_code == 2
    assert "objective" not in captured
    assert "--objective is required" in capsys.readouterr().err
