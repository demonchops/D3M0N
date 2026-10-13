"""Every external-binary tool must fail soft (return an 'error' dict with an
install hint) rather than raise, when its binary isn't on PATH."""

from d3m0n.tools.fuzz import ffuf_scan
from d3m0n.tools.scan import nmap_scan
from d3m0n.tools.subdomain import subfinder_scan
from d3m0n.tools.vuln import nuclei_scan


def test_nmap_skips_cleanly_when_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    result = nmap_scan("example.com")
    assert "error" in result
    assert "not installed" in result["error"]


def test_subfinder_skips_cleanly_when_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    result = subfinder_scan("example.com")
    assert "error" in result
    assert "not installed" in result["error"]


def test_nuclei_skips_cleanly_when_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    result = nuclei_scan("example.com")
    assert "error" in result
    assert "not installed" in result["error"]


def test_ffuf_skips_cleanly_when_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    result = ffuf_scan("example.com")
    assert "error" in result
    assert "not installed" in result["error"]
