"""run_defense_mapper: strict-JSON parsing of the one-shot remediation/
detection-rule generation call, and that it degrades gracefully (never
raises) on every failure mode a text completion can hand back."""

from d3m0n.agent.defense_mapper import run_defense_mapper


class _FakeTextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _FakeResponse:
    def __init__(self, text):
        self.content = [_FakeTextBlock(text)]


class _FakeMessages:
    def __init__(self, text):
        self._text = text

    def create(self, **kwargs):
        return _FakeResponse(self._text)


class _FakeClient:
    def __init__(self, text):
        self.messages = _FakeMessages(text)


class _RaisingClient:
    def __init__(self, exc):
        self._exc = exc

    @property
    def messages(self):
        raise self._exc


def test_valid_json_array_parsed_into_entries():
    client = _FakeClient(
        '[{"finding_summary": "Reflected XSS on /search", '
        '"remediation": "Encode output.", "detection_ideas": "Alert on unescaped <script in responses."}]'
    )
    result = run_defense_mapper(client, "objective", "example.com", [{"tool": "x"}])

    assert result["generation_error"] is None
    assert len(result["entries"]) == 1
    assert result["entries"][0]["finding_summary"] == "Reflected XSS on /search"


def test_markdown_fenced_json_still_parses():
    client = _FakeClient(
        '```json\n[{"finding_summary": "x", "remediation": "y", "detection_ideas": "z"}]\n```'
    )
    result = run_defense_mapper(client, "objective", "example.com", [])
    assert result["generation_error"] is None
    assert len(result["entries"]) == 1


def test_empty_array_is_a_valid_clean_result():
    client = _FakeClient("[]")
    result = run_defense_mapper(client, "objective", "example.com", [])
    assert result == {"entries": [], "generation_error": None}


def test_malformed_json_falls_back_with_generation_error_set():
    client = _FakeClient("not even json {{{")
    result = run_defense_mapper(client, "objective", "example.com", [])
    assert result["entries"] == []
    assert result["generation_error"] is not None


def test_non_array_json_falls_back_with_generation_error_set():
    client = _FakeClient('{"not": "an array"}')
    result = run_defense_mapper(client, "objective", "example.com", [])
    assert result["entries"] == []
    assert result["generation_error"] is not None


def test_non_object_entries_in_array_are_skipped_not_fatal():
    client = _FakeClient('["just a string", {"finding_summary": "real one", "remediation": "r", "detection_ideas": "d"}]')
    result = run_defense_mapper(client, "objective", "example.com", [])
    assert result["generation_error"] is None
    assert len(result["entries"]) == 1
    assert result["entries"][0]["finding_summary"] == "real one"


def test_missing_fields_in_an_entry_default_to_empty_string():
    client = _FakeClient('[{"finding_summary": "x"}]')
    result = run_defense_mapper(client, "objective", "example.com", [])
    assert result["entries"][0]["remediation"] == ""
    assert result["entries"][0]["detection_ideas"] == ""


def test_client_exception_falls_back_cleanly():
    client = _RaisingClient(RuntimeError("ANTHROPIC_API_KEY is not set."))
    result = run_defense_mapper(client, "objective", "example.com", [])
    assert result["entries"] == []
    assert "ANTHROPIC_API_KEY" in result["generation_error"]


def test_empty_text_response_treated_as_empty_array():
    client = _FakeClient("")
    result = run_defense_mapper(client, "objective", "example.com", [])
    assert result == {"entries": [], "generation_error": None}


def test_fields_truncated_to_limit():
    from d3m0n.agent.defense_mapper import _FIELD_CHAR_LIMIT
    import json

    long_text = "x" * (_FIELD_CHAR_LIMIT + 500)
    client = _FakeClient(
        json.dumps([{"finding_summary": long_text, "remediation": "r", "detection_ideas": "d"}])
    )
    result = run_defense_mapper(client, "objective", "example.com", [])
    assert len(result["entries"][0]["finding_summary"]) == _FIELD_CHAR_LIMIT
