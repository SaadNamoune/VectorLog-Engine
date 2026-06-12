from __future__ import annotations

import smtplib
from dataclasses import dataclass
from datetime import datetime
from email.mime.text import MIMEText
from typing import Any

from .config import Settings, load_settings


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Alert:
    title: str
    severity: str
    message: str
    source: str
    timestamp: datetime
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


def _should_dispatch(alert: Alert, threshold: str) -> bool:
    return SEVERITY_RANK.get(alert.severity, 0) >= SEVERITY_RANK.get(threshold, 0)


def dispatch_email(alert: Alert, settings: Settings) -> bool:
    if not settings.alert_smtp_host or not settings.alert_to_email:
        return False
    try:
        body = (
            f"[VectorLog-Engine Alert]\n\n"
            f"Severity : {alert.severity.upper()}\n"
            f"Source   : {alert.source}\n"
            f"Time     : {alert.timestamp.isoformat()}\n\n"
            f"{alert.message}\n\n"
            f"Metadata : {alert.metadata}"
        )
        msg = MIMEText(body)
        msg["Subject"] = f"[{alert.severity.upper()}] {alert.title}"
        msg["From"] = settings.alert_from_email
        msg["To"] = settings.alert_to_email
        with smtplib.SMTP(settings.alert_smtp_host, settings.alert_smtp_port, timeout=10) as server:
            server.starttls()
            server.send_message(msg)
        return True
    except Exception:
        return False


def dispatch(alert: Alert, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or load_settings()
    if not _should_dispatch(alert, settings.alert_severity_threshold):
        return {"dispatched": False, "reason": "below threshold"}
    email_sent = dispatch_email(alert, settings)
    return {"dispatched": True, "email": email_sent, "alert": alert.to_dict()}


def anomaly_alert(score_result: dict[str, Any], log_source: str = "unknown") -> Alert:
    return Alert(
        title=f"Anomalous log detected — {score_result.get('severity', 'unknown').upper()}",
        severity=score_result.get("severity", "low"),
        message=score_result.get("message", ""),
        source=log_source,
        timestamp=datetime.utcnow(),
        metadata={
            "anomaly_probability": score_result.get("anomaly_probability"),
            "raw_score": score_result.get("raw_score"),
        },
    )
