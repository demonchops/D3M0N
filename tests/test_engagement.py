"""engagement.py: the structured scope+objectives config, its JSON/YAML
loading, and that it enforces the exact same authorization rule as a
plain scope file (not a second, divergent copy of that rule)."""

import pytest
from pydantic import ValidationError

from d3m0n.engagement import (
    EngagementConfig,
    Objective,
    engagement_scope,
    load_engagement_config,
    objectives_summary,
)
from d3m0n.safety import ScopeFileError


def _authorized_config(**overrides) -> EngagementConfig:
    defaults = dict(
        program="Test Program",
        scope="*.example.com",
        authorized=True,
        confirmed_by="tester",
    )
    defaults.update(overrides)
    return EngagementConfig(**defaults)


def test_valid_config_round_trips_through_engagement_scope():
    config = _authorized_config()
    scope, meta = engagement_scope(config)
    assert scope.raw == "*.example.com"
    assert scope.contains("sub.example.com")
    assert meta["confirmed_by"] == "tester"
    assert meta["program"] == "Test Program"


def test_not_authorized_rejected():
    config = _authorized_config(authorized=False)
    with pytest.raises(ScopeFileError, match="authorized"):
        engagement_scope(config)


def test_missing_confirmed_by_rejected():
    config = _authorized_config(confirmed_by=None)
    with pytest.raises(ScopeFileError, match="confirmed_by"):
        engagement_scope(config)


def test_unspecified_confirmed_at_falls_back_cleanly():
    # Regression: Pydantic's model_dump() always materializes every
    # field (confirmed_at=None rather than the key being absent), which
    # defeats a plain dict.get(key, default) -- the fallback has to
    # trigger on None too, not just on the key being missing.
    config = _authorized_config()
    _, meta = engagement_scope(config)
    assert meta["confirmed_at"] == "<unspecified>"


def test_phase_must_be_one_of_the_known_set():
    with pytest.raises(ValidationError):
        Objective(phase="launch_nukes", description="x")


def test_valid_phases_all_accepted():
    for phase in ("recon", "map", "detect", "access_control", "defend", "verify"):
        Objective(phase=phase, description="x")  # must not raise


def test_unknown_top_level_field_rejected():
    with pytest.raises(ValidationError):
        EngagementConfig(scope="example.com", unexpected_field="x")


def test_objectives_summary_lists_pending_in_order():
    config = _authorized_config(
        objectives=[
            Objective(phase="recon", description="enumerate subdomains"),
            Objective(phase="detect", description="run nuclei"),
        ]
    )
    summary = objectives_summary(config)
    assert "recon" in summary
    assert "detect" in summary
    assert summary.index("enumerate subdomains") < summary.index("run nuclei")


def test_objectives_summary_skips_done_objectives():
    config = _authorized_config(
        objectives=[
            Objective(phase="recon", description="already finished", done=True),
            Objective(phase="verify", description="still pending"),
        ]
    )
    summary = objectives_summary(config)
    assert "already finished" not in summary
    assert "still pending" in summary


def test_objectives_summary_empty_when_no_objectives():
    assert objectives_summary(_authorized_config()) == ""


def test_objectives_summary_empty_when_all_done():
    config = _authorized_config(
        objectives=[Objective(phase="recon", description="x", done=True)]
    )
    assert objectives_summary(config) == ""


# --- file loading: JSON, YAML, and error paths ---


def test_load_json_engagement_file(tmp_path):
    path = tmp_path / "engagement.json"
    path.write_text(
        """
        {
          "program": "Acme Bounty",
          "scope": "*.acme.com",
          "authorized": true,
          "confirmed_by": "me",
          "objectives": [
            {"phase": "recon", "description": "enumerate subdomains"}
          ]
        }
        """
    )
    config = load_engagement_config(str(path))
    assert config.program == "Acme Bounty"
    assert len(config.objectives) == 1
    assert config.objectives[0].phase == "recon"


def test_load_yaml_engagement_file(tmp_path):
    path = tmp_path / "engagement.yaml"
    path.write_text(
        """
        program: Acme Bounty
        scope: "*.acme.com"
        authorized: true
        confirmed_by: me
        objectives:
          - phase: recon
            description: enumerate subdomains
          - phase: detect
            description: run nuclei
        """
    )
    config = load_engagement_config(str(path))
    assert config.program == "Acme Bounty"
    assert [o.phase for o in config.objectives] == ["recon", "detect"]


def test_load_yml_extension_also_treated_as_yaml(tmp_path):
    path = tmp_path / "engagement.yml"
    path.write_text("scope: example.com\nauthorized: true\nconfirmed_by: me\n")
    config = load_engagement_config(str(path))
    assert config.scope == "example.com"


def test_missing_file_raises_scope_file_error(tmp_path):
    with pytest.raises(ScopeFileError, match="not found"):
        load_engagement_config(str(tmp_path / "nope.json"))


def test_invalid_json_raises_scope_file_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not even json {{{")
    with pytest.raises(ScopeFileError, match="not valid JSON"):
        load_engagement_config(str(path))


def test_invalid_yaml_raises_scope_file_error(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("key: value:\n  bad: [unclosed")
    with pytest.raises(ScopeFileError, match="not valid YAML"):
        load_engagement_config(str(path))


def test_non_object_json_top_level_rejected(tmp_path):
    path = tmp_path / "array.json"
    path.write_text('["not", "an", "object"]')
    with pytest.raises(ScopeFileError, match="object/mapping"):
        load_engagement_config(str(path))


def test_bad_phase_in_file_raises_scope_file_error(tmp_path):
    path = tmp_path / "bad_phase.json"
    path.write_text(
        '{"scope": "example.com", "authorized": true, "confirmed_by": "me", '
        '"objectives": [{"phase": "nonsense", "description": "x"}]}'
    )
    with pytest.raises(ScopeFileError, match="invalid"):
        load_engagement_config(str(path))


def test_directory_path_raises_scope_file_error(tmp_path):
    with pytest.raises(ScopeFileError, match="directory"):
        load_engagement_config(str(tmp_path))


def test_example_json_shipped_in_repo_is_well_formed_but_not_authorized():
    # Mirrors scope.example.json's own safe-by-default pattern: it must
    # load and validate cleanly, but must fail the authorization check
    # unedited, so copying it as-is can never accidentally authorize a run.
    config = load_engagement_config("engagement.example.json")
    with pytest.raises(ScopeFileError, match="authorized"):
        engagement_scope(config)
