"""
Snitch — classifier tests.

EN: Covers the classification priority: tracker domains > CDN > well-known
    ports > unknown fallback.
FR: Couvre la priorité de classification : domaines trackers > CDN > ports
    connus > repli « unknown ».
"""

from classifier.traffic import classify


def test_tracker_domain_wins_over_port():
    """EN: A tracker hostname on 443 is still 'tracking', not 'safe'.
    FR: Un hostname tracker sur 443 reste « tracking », pas « safe »."""
    r = classify("stats.doubleclick.net", 443, "TCP")
    assert r.category == "tracking"
    assert r.label == "HTTPS"


def test_cdn_domain():
    r = classify("cdn.cloudflare.com", 443, "TCP")
    assert r.category == "cdn"


def test_https_port_is_safe():
    r = classify("example.com", 443, "TCP")
    assert r.category == "safe"


def test_dns_port():
    r = classify(None, 53, "UDP")
    assert r.category == "dns"
    assert r.label == "DNS"


def test_ssh_is_admin():
    r = classify(None, 22, "TCP")
    assert r.category == "admin"


def test_unknown_port_falls_back_to_protocol_label():
    r = classify(None, 9999, "TCP")
    assert r.category == "unknown"
    assert r.label == "TCP"


def test_suffix_match_rejects_lookalike_domain():
    """EN: "notdoubleclick.net" contains "doubleclick.net" as a substring but
    is NOT a subdomain — the old `in` test falsely flagged it.
    FR: « notdoubleclick.net » contient « doubleclick.net » en sous-chaîne
    mais n'est PAS un sous-domaine — l'ancien test `in` le signalait à tort."""
    r = classify("notdoubleclick.net", 443, "TCP")
    assert r.category == "safe"


def test_suffix_match_accepts_deep_subdomain():
    """EN: a.b.c.doubleclick.net still matches doubleclick.net by suffix.
    FR: a.b.c.doubleclick.net correspond toujours à doubleclick.net."""
    r = classify("a.b.c.doubleclick.net", 443, "TCP")
    assert r.category == "tracking"
