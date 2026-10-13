import pytest

from d3m0n.safety import OutOfScopeError, enforce_scope, parse_scope


def test_parses_mixed_scope():
    scope = parse_scope("example.com, 10.0.0.0/24, 192.168.1.5")
    assert scope.hostnames == ("example.com",)
    assert len(scope.networks) == 2


def test_hostname_in_scope_matches_subdomain():
    scope = parse_scope("example.com")
    assert scope.contains("api.example.com")
    assert scope.contains("example.com")
    assert not scope.contains("notexample.com")
    assert not scope.contains("example.com.evil.net")


def test_ip_in_scope_cidr():
    scope = parse_scope("10.0.0.0/24")
    assert scope.contains("10.0.0.5")
    assert not scope.contains("10.0.1.5")


def test_full_url_target_resolves_to_hostname():
    # A tool schema may hand over a full URL ("URL or hostname") rather than
    # a bare host — contains() must extract the hostname before matching,
    # not reject the whole string as unparseable.
    scope = parse_scope("example.com")
    assert scope.contains("https://api.example.com/v1/users?id=1")
    assert scope.contains("http://example.com:8080/path")
    assert not scope.contains("https://evil.com/example.com")


def test_full_url_target_ip_in_cidr():
    scope = parse_scope("10.0.0.0/24")
    assert scope.contains("http://10.0.0.5:8080/admin")


def test_enforce_scope_raises_on_violation():
    scope = parse_scope("example.com")
    with pytest.raises(OutOfScopeError):
        enforce_scope(scope, "evil.com")


def test_enforce_scope_passes_in_scope():
    scope = parse_scope("example.com")
    enforce_scope(scope, "www.example.com")  # should not raise


def test_empty_scope_rejected():
    with pytest.raises(ValueError):
        parse_scope("")
