"""write_report: the saved JSON actually includes the summary (and the
pre-review draft, when a critic pass revised it)."""

import json

from d3m0n.tools.report import write_report


def test_report_includes_summary(tmp_path):
    path = write_report(
        str(tmp_path), "test objective", "example.com", [], summary="Final summary text."
    )
    data = json.loads(open(path).read())
    assert data["summary"] == "Final summary text."
    assert data["objective"] == "test objective"
    assert "summary_before_critic_self_review" not in data


def test_report_includes_pre_critic_draft_when_present(tmp_path):
    path = write_report(
        str(tmp_path),
        "test objective",
        "example.com",
        [],
        summary="Revised summary.",
        summary_before_critic="Original overclaiming draft.",
    )
    data = json.loads(open(path).read())
    assert data["summary"] == "Revised summary."
    assert data["summary_before_critic_self_review"] == "Original overclaiming draft."


def test_report_includes_defense_recommendations_when_present(tmp_path):
    recs = {"entries": [{"finding_summary": "x", "remediation": "y", "detection_ideas": "z"}], "generation_error": None}
    path = write_report(
        str(tmp_path), "test objective", "example.com", [], summary="Summary.", defense_recommendations=recs
    )
    data = json.loads(open(path).read())
    assert data["defense_recommendations"] == recs


def test_report_omits_defense_recommendations_when_absent(tmp_path):
    path = write_report(str(tmp_path), "test objective", "example.com", [], summary="Summary.")
    data = json.loads(open(path).read())
    assert "defense_recommendations" not in data
