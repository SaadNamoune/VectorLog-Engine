from __future__ import annotations

import pytest
from vectorlog.threat_intel import enrich_ip, extract_and_enrich


class TestEnrichIP:
    def test_private_ip(self):
        result = enrich_ip("192.168.1.100")
        assert result.is_private is True
        assert "private" in result.tags
        assert result.risk_score == 0.0

    def test_loopback(self):
        result = enrich_ip("127.0.0.1")
        assert "loopback" in result.tags

    def test_public_ip_low_risk(self):
        result = enrich_ip("8.8.8.8")
        assert result.is_private is False
        assert result.risk_score > 0.0

    def test_invalid_ip(self):
        result = enrich_ip("not_an_ip")
        assert "invalid" in result.tags

    def test_bogon_range(self):
        result = enrich_ip("0.0.0.1")
        assert result.is_bogon is True


class TestExtractAndEnrich:
    def test_extracts_ips_from_text(self):
        text = "Failed password from 218.145.123.45 port 22"
        result = extract_and_enrich(text)
        assert result["ip_count"] == 1
        assert result["indicators"][0]["value"] == "218.145.123.45"

    def test_no_ips(self):
        result = extract_and_enrich("no ip address here at all")
        assert result["ip_count"] == 0
        assert result["overall_risk"] == 0.0

    def test_multiple_ips(self):
        text = "src=10.0.0.1 dst=8.8.8.8 attacker=1.2.3.4"
        result = extract_and_enrich(text)
        assert result["ip_count"] == 3
