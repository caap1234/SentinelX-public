# app/services/notification_dispatch.py
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlencode

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.user_setting import UserSetting
from app.services.emailer import send_email, smtp_configured


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_user_alert_email_pref(db: Session, user_id: int) -> Dict[str, Any]:
    row = (
        db.query(UserSetting)
        .filter(UserSetting.user_id == int(user_id), UserSetting.key == "alert_email")
        .first()
    )
    if not row or not (row.value or "").strip():
        return {"high": True, "medium": True, "low": True, "to_email": None}

    try:
        data = json.loads(row.value)
        if not isinstance(data, dict):
            raise ValueError("not dict")
    except Exception:
        return {"high": True, "medium": True, "low": True, "to_email": None}

    return {
        "high": bool(data.get("high", True)),
        "medium": bool(data.get("medium", True)),
        "low": bool(data.get("low", True)),
        "to_email": (str(data.get("to_email")).strip() if data.get("to_email") else None),
    }


def _bucket_from_score(score: int) -> str:
    n = int(score or 0)
    if n >= 61:
        return "high"
    if n >= 31:
        return "medium"
    return "low"


def _fmt_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        return str(obj)


def _record_email_result(alert: Alert, *, to_email: str, ok: bool, error: Optional[str]) -> None:
    metrics = alert.metrics if isinstance(alert.metrics, dict) else {}
    entries = metrics.get("email_notifications")
    if not isinstance(entries, list):
        entries = []

    entries.append(
        {
            "ts": _utcnow_iso(),
            "to_email": to_email,
            "ok": bool(ok),
            "error": (error or None),
        }
    )

    metrics["email_notifications"] = entries
    alert.metrics = metrics


def _frontend_base_url() -> str:
    """
    En tu proyecto, usualmente ya existe FRONTEND_BASE_URL.
    Si no existe en env, usa prod o localhost.
    """
    # Import local para evitar ciclos si app.config hace cosas en import
    try:
        from app.config import settings  # type: ignore
        base = (getattr(settings, "FRONTEND_BASE_URL", "") or "").strip()
        if base:
            return base.rstrip("/")
    except Exception:
        pass

    # fallback (ajusta si quieres)
    return "https://sentinelx.tokyo-03.com".rstrip("/")


def _alert_links(alert: Alert) -> Dict[str, str]:
    """
    Links:
      - direct: intenta enfocar alerta en UI
      - open_list: tu lista de alertas abiertas (por defecto)
    """
    base = _frontend_base_url()

    # Lista “open” como tú pediste
    open_list = f"{base}/dashboard/alertas/?" + urlencode(
        {"page": 1, "days": 7, "severity": "all", "status": "open"}
    )

    # Directo (mejor esfuerzo): enfocar la alerta.
    # Si tu UI no soporta focus_alert_id, igual cae a la lista.
    direct = f"{base}/dashboard/alertas/?" + urlencode(
        {
            "page": 1,
            "days": 7,
            "severity": "all",
            "status": "all",
            "focus_alert_id": str(getattr(alert, "id", "")),
        }
    )

    return {"direct": direct, "open_list": open_list}


def notify_on_alert_created(
    *,
    db: Session,
    alert: Alert,
    user_id: int,
) -> None:
    if not smtp_configured():
        return

    prefs = _get_user_alert_email_pref(db, user_id)
    to_email = prefs.get("to_email")
    if not to_email:
        return

    # Alert.severity: 0-9 low, 10-17 medium, 18-30 high
    sev = int(getattr(alert, "severity", 0) or 0)
    bucket = "high" if sev >= 18 else ("medium" if sev >= 10 else "low")

    if not prefs.get(bucket, True):
        return

    links = _alert_links(alert)

    subject = f"[SentinelX] Alerta {bucket.upper()} · {alert.rule_name or 'Alert'}"

    # Texto “Slack-friendly”: corto, con secciones y links en líneas separadas
    body = "\n".join(
        [
            "SENTINELX · ALERTA",
            "-" * 32,
            f"Rule: {alert.rule_name}",
            f"Server: {alert.server or '-'}",
            f"Severity: {sev} ({bucket})",
            f"Group: {alert.group_key}",
            f"Status: {alert.status}",
            f"Triggered: {alert.triggered_at.isoformat() if getattr(alert, 'triggered_at', None) else '-'}",
            "",
            "Links:",
            f"- Ver esta alerta: {links['direct']}",
            f"- Ver alertas abiertas: {links['open_list']}",
            "",
            "Metrics:",
            _fmt_json(alert.metrics or {}),
            "",
            "Evidence:",
            _fmt_json(alert.evidence or {}),
        ]
    )

    # HTML opcional (para clientes normales). Slack email normalmente toma texto, pero no estorba.
    html = f"""
    <div style="font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; font-size:14px; color:#111827;">
      <div style="font-size:12px; letter-spacing:.08em; color:#6B7280;">SENTINELX · ALERTA</div>
      <h2 style="margin:6px 0 10px 0; font-size:16px;">{(alert.rule_name or "Alert")}</h2>
      <table style="border-collapse:collapse; font-size:13px;">
        <tr><td style="padding:2px 10px 2px 0; color:#6B7280;">Server</td><td style="padding:2px 0;">{alert.server or "-"}</td></tr>
        <tr><td style="padding:2px 10px 2px 0; color:#6B7280;">Severity</td><td style="padding:2px 0;">{sev} ({bucket})</td></tr>
        <tr><td style="padding:2px 10px 2px 0; color:#6B7280;">Status</td><td style="padding:2px 0;">{alert.status}</td></tr>
        <tr><td style="padding:2px 10px 2px 0; color:#6B7280;">Triggered</td><td style="padding:2px 0;">{alert.triggered_at.isoformat() if getattr(alert, 'triggered_at', None) else "-"}</td></tr>
      </table>

      <div style="margin:12px 0 6px 0; font-weight:600;">Links</div>
      <ul style="margin:0; padding-left:18px;">
        <li><a href="{links['direct']}">Ver esta alerta</a></li>
        <li><a href="{links['open_list']}">Ver alertas abiertas</a></li>
      </ul>

      <details style="margin-top:12px;">
        <summary style="cursor:pointer; color:#111827; font-weight:600;">Metrics</summary>
        <pre style="background:#F9FAFB; border:1px solid #E5E7EB; padding:10px; border-radius:10px; overflow:auto;">{_fmt_json(alert.metrics or {})}</pre>
      </details>

      <details style="margin-top:10px;">
        <summary style="cursor:pointer; color:#111827; font-weight:600;">Evidence</summary>
        <pre style="background:#F9FAFB; border:1px solid #E5E7EB; padding:10px; border-radius:10px; overflow:auto;">{_fmt_json(alert.evidence or {})}</pre>
      </details>
    </div>
    """.strip()

    ok, err = send_email(to_email=to_email, subject=subject, text_body=body, html_body=html)
    _record_email_result(alert, to_email=to_email, ok=ok, error=err)

    # aseguramos que quede persistido si el caller hace commit
    db.flush()


def notify_on_incident_created(
    *,
    db: Session,
    incident: Incident,
    user_id: int,
) -> None:
    if not smtp_configured():
        return

    prefs = _get_user_alert_email_pref(db, user_id)
    to_email = prefs.get("to_email")
    if not to_email:
        return

    score = int(getattr(incident, "score", 0) or 0)
    bucket = _bucket_from_score(score)

    if not prefs.get(bucket, True):
        return

    subject = f"[SentinelX] Incidente {bucket.upper()} · {incident.code or 'INC'}"

    base = _frontend_base_url()
    # Lista de incidentes “pendientes” (ajústalo si tu ruta es distinta)
    incidents_open = f"{base}/dashboard/incidentes/?{urlencode({'page': 1, 'days': 7, 'status': 'open'})}"

    body = "\n".join(
        [
            "SENTINELX · INCIDENTE",
            "-" * 32,
            f"Code: {incident.code}",
            f"Name: {incident.name}",
            f"Scope: {incident.scope}",
            f"Server: {incident.server or '-'}",
            f"Score: {score} ({bucket})",
            f"Status: {incident.status}",
            f"Primary: {incident.primary_entity_type}:{incident.primary_entity_key}",
            "",
            "Links:",
            f"- Ver incidentes pendientes: {incidents_open}",
            "",
            "Metrics:",
            _fmt_json(incident.metrics if isinstance(incident.metrics, dict) else {}),
            "",
            "Evidence:",
            _fmt_json(incident.evidence if isinstance(incident.evidence, dict) else {}),
        ]
    )

    ok, err = send_email(to_email=to_email, subject=subject, text_body=body)

    metrics = incident.metrics if isinstance(incident.metrics, dict) else {}
    entries = metrics.get("email_notifications")
    if not isinstance(entries, list):
        entries = []
    entries.append({"ts": _utcnow_iso(), "to_email": to_email, "ok": bool(ok), "error": (err or None)})
    metrics["email_notifications"] = entries
    incident.metrics = metrics

    db.flush()

