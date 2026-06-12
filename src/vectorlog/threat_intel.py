from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any


# Curated list of known malicious IP ranges and patterns for offline enrichment.
# In production, replace with AbuseIPDB / VirusTotal / AlienVault OTX API calls.

_BOGON_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "240.0.0.0/4", "255.255.255.255/32",
]
_BOGON_NETWORKS = [ipaddress.ip_network(r) for r in _BOGON_RANGES]

_HIGH_RISK_ASNS: set[str] = {"AS14061", "AS16276", "AS24940", "AS20473"}

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")


@dataclass
class ThreatIndicator:
    value: str
    indicator_type: str
    is_bogon: bool = False
    is_private: bool = False
    risk_score: float = 0.0
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def enrich_ip(ip_str: str) -> ThreatIndicator:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return ThreatIndicator(value=ip_str, indicator_type="ip", tags=["invalid"])

    is_private = addr.is_private
    is_bogon = any(addr in net for net in _BOGON_NETWORKS)
    tags = []
    if is_private:
        tags.append("private")
    if is_bogon:
        tags.append("bogon")
    if addr.is_loopback:
        tags.append("loopback")
    if addr.is_multicast:
        tags.append("multicast")

    risk_score = 0.0
    if not is_private and not is_bogon:
        risk_score = 0.3
    if is_bogon and not is_private:
        risk_score = 0.7
        tags.append("suspicious-bogon")

    return ThreatIndicator(
        value=ip_str,
        indicator_type="ip",
        is_bogon=is_bogon,
        is_private=is_private,
        risk_score=risk_score,
        tags=tags,
        metadata={"version": addr.version},
    )


def extract_and_enrich(text: str) -> dict[str, Any]:
    ips = list(set(_IP_RE.findall(text)))
    indicators = [enrich_ip(ip) for ip in ips]
    high_risk = [i for i in indicators if i.risk_score >= 0.5]
    return {
        "raw_text": text,
        "ip_count": len(ips),
        "indicators": [
            {
                "value": ind.value,
                "type": ind.indicator_type,
                "risk_score": ind.risk_score,
                "tags": ind.tags,
                "is_private": ind.is_private,
            }
            for ind in indicators
        ],
        "high_risk_count": len(high_risk),
        "overall_risk": max((i.risk_score for i in indicators), default=0.0),
    }
