from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert
from app.models.incident_rule import IncidentRule
from app.models.incident_rule_state import IncidentRuleState


# ----------------------------
# Safe expression evaluation (mismo enfoque que RuleEngineV2)
# ----------------------------

_ALLOWED_NODES = (
    ast.Expression,
    ast.BoolOp, ast.And, ast.Or,
    ast.UnaryOp, ast.Not,
    ast.Compare, ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE, ast.In, ast.NotIn,
    ast.Name, ast.Load,
    ast.Constant,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod,
)

_ALLOWED_NAMES = {"True": True, "False": False, "None": None}


def _safe_eval(expr: str, ctx: Dict[str, Any]) -> bool:
    if not expr:
        return True
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise ValueError(f"Expr node not allowed: {type(node).__name__}")
        if isinstance(node, ast.Name) and node.id not in ctx and node.id not in _ALLOWED_NAMES:
            raise ValueError(f"Unknown name in expr: {node.id}")
    code = compile(tree, "<incident_rule_condition>", "eval")
    return bool(eval(code, {"__builtins__": {}}, {**_ALLOWED_NAMES, **ctx}))


def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _as_str(v: Any) -> str:
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return ""


def _extract_group_values(alert: Alert) -> Dict[str, Any]:
    """
    Espera que RuleEngineV2 meta en alert.evidence:
      evidence.group_values: { "server": "...", "ip_client": "...", "username": "...", "extra.vhost": "..." }
    Fallback: {}.
    """
    ev = alert.evidence or {}
    if isinstance(ev, dict):
        gv = ev.get("group_values")
        if isinstance(gv, dict):
            return gv
    return {}


def _build_group_key(group_by: List[str], group_values: Dict[str, Any]) -> str:
    parts: List[str] = []
    for f in group_by:
        v = group_values.get(f)
        parts.append(_as_str(v) if v is not None and _as_str(v) != "" else "-")
    return "|".join(parts)


def _match_rule(alert: Alert, rule: IncidentRule) -> bool:
    """
    match soportado:
      - alert_codes_any: [ "AUTH-003", ... ] (contra alert.rule_name exact o prefijo)
      - alert_names_any: [ "SSH brute force detected", ... ]
      - min_severity: int
      - server_any: [ "svdb057", ... ]
    """
    m = rule.match or {}
    if not isinstance(m, dict) or not m:
        return True

    alert_rule_name = _as_str(getattr(alert, "rule_name", None)).strip()

    if "alert_codes_any" in m:
        codes = [c.strip() for c in _as_list(m.get("alert_codes_any")) if _as_str(c).strip()]
        ok = False
        for c in codes:
            if (
                alert_rule_name == c
                or alert_rule_name.startswith(f"{c} ")
                or alert_rule_name.startswith(f"{c}\t")
                or alert_rule_name.startswith(f"{c}-")
                or alert_rule_name.startswith(f"{c}:")
            ):
                ok = True
                break
        if not ok:
            return False

    if "alert_names_any" in m:
        names = [n.strip() for n in _as_list(m.get("alert_names_any")) if _as_str(n).strip()]
        if alert_rule_name not in names:
            return False

    if "min_severity" in m:
        try:
            minsev = int(m.get("min_severity"))
        except Exception:
            minsev = 0
        try:
            sev = int(getattr(alert, "severity", 0) or 0)
        except Exception:
            sev = 0
        if sev < minsev:
            return False

    if "server_any" in m:
        servers = [s.strip() for s in _as_list(m.get("server_any")) if _as_str(s).strip()]
        if servers:
            if _as_str(getattr(alert, "server", None)).strip() not in servers:
                return False

    return True


@dataclass
class _Agg:
    count: int
    unique_alerts: int
    unique_servers: int
    max_severity: int
    sum_severity: int
    first_ts: datetime
    last_ts: datetime
    alert_ids: List[int]


class IncidentEngine:
    def __init__(self) -> None:
        self._rules: List[IncidentRule] = []

    def reload_rules(self, db: Session) -> None:
        self._rules = (
            db.query(IncidentRule)
            .filter(IncidentRule.enabled.is_(True))
            .order_by(IncidentRule.id.asc())
            .all()
        )

    def run(self, db: Session, now: Optional[datetime] = None) -> List[Incident]:
        """
        Genera/actualiza incidentes evaluando reglas contra alertas en ventana.
        - Idempotencia por cooldown (IncidentRuleState por group_key).
        - Asocia IncidentAlert con las alertas dentro de la ventana que cumplieron.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        now = _utc(now) or datetime.now(timezone.utc)

        created_or_updated: List[Incident] = []

        for rule in self._rules:
            win = int(rule.window_seconds or 1800)
            cooldown = int(rule.cooldown_seconds or 3600)
            window_start = now - timedelta(seconds=win)

            q = (
                db.query(Alert)
                .filter(Alert.triggered_at >= window_start, Alert.triggered_at <= now)
                .order_by(Alert.triggered_at.asc())
            )

            m = rule.match or {}
            if isinstance(m, dict) and "server_any" in m:
                servers = [s.strip() for s in _as_list(m.get("server_any")) if _as_str(s).strip()]
                if servers:
                    q = q.filter(Alert.server.in_(servers))

            alerts = q.all()
            if not alerts:
                continue

            group_by = [str(x) for x in _as_list(rule.group_by) if _as_str(x).strip()]
            if not group_by:
                pef = _as_str(getattr(rule, "primary_entity_field", None)).strip()
                group_by = ["server"] + ([pef] if pef else [])

            buckets: Dict[str, List[Alert]] = {}
            group_values_by_key: Dict[str, Dict[str, Any]] = {}

            for al in alerts:
                if not _match_rule(al, rule):
                    continue

                gv = _extract_group_values(al)
                gk = _build_group_key(group_by, gv)
                if gk not in buckets:
                    buckets[gk] = []
                    group_values_by_key[gk] = gv
                buckets[gk].append(al)

            if not buckets:
                continue

            for group_key, items in buckets.items():
                state = (
                    db.query(IncidentRuleState)
                    .filter(
                        IncidentRuleState.rule_id == rule.id,
                        IncidentRuleState.group_key == group_key,
                    )
                    .first()
                )
                if not state:
                    state = IncidentRuleState(rule_id=rule.id, group_key=group_key)
                    db.add(state)
                    db.flush()

                state.last_seen_at = now

                if cooldown > 0 and state.last_incident_at:
                    last_inc = _utc(state.last_incident_at)
                    if last_inc and now < last_inc + timedelta(seconds=cooldown):
                        db.add(state)
                        continue

                alert_ids = [int(a.id) for a in items if a.id is not None]
                unique_servers = len({(_as_str(a.server).strip() or "-") for a in items})
                max_sev = 0
                sum_sev = 0
                for a in items:
                    try:
                        s = int(a.severity or 0)
                    except Exception:
                        s = 0
                    max_sev = max(max_sev, s)
                    sum_sev += s

                agg = _Agg(
                    count=len(items),
                    unique_alerts=len({(_as_str(a.rule_name).strip() or "-") for a in items}),
                    unique_servers=unique_servers,
                    max_severity=max_sev,
                    sum_severity=sum_sev,
                    first_ts=_utc(items[0].triggered_at) or now,
                    last_ts=_utc(items[-1].triggered_at) or now,
                    alert_ids=alert_ids,
                )

                gv = group_values_by_key.get(group_key, {})
                primary_field = _as_str(getattr(rule, "primary_entity_field", None)).strip()
                primary_val = gv.get(primary_field) if primary_field else None

                ctx: Dict[str, Any] = {
                    "count": agg.count,
                    "unique_alerts": agg.unique_alerts,
                    "unique_servers": agg.unique_servers,
                    "max_severity": agg.max_severity,
                    "sum_severity": agg.sum_severity,
                    "window_seconds": win,
                    "group_key": group_key,
                    "primary": primary_val,
                    "server": gv.get("server"),
                }

                cond = (rule.condition or "").strip()
                try:
                    ok = _safe_eval(cond, ctx)
                except Exception as e:
                    ex = dict(state.extra or {})
                    ex["last_condition_error"] = f"{type(e).__name__}: {e}"
                    ex["last_condition_expr"] = cond
                    state.extra = ex
                    db.add(state)
                    continue

                if not ok:
                    db.add(state)
                    continue

                primary_key = _as_str(primary_val).strip()
                if not primary_key:
                    db.add(state)
                    continue

                inc = (
                    db.query(Incident)
                    .filter(
                        Incident.status.in_(["open", "triage", "contained"]),
                        Incident.code == rule.code,
                        Incident.primary_entity_type == rule.primary_entity_type,
                        Incident.primary_entity_key == primary_key,
                    )
                    .order_by(Incident.opened_at.desc())
                    .first()
                )

                base = int(rule.severity_base or 10)
                bonus = int(rule.score_bonus or 0)
                score = max(0, min(100, base + bonus))

                if not inc:
                    inc = Incident(
                        code=rule.code,
                        name=rule.name,
                        scope=(rule.scope or "local"),
                        status="open",
                        severity_base=base,
                        severity_current=base,
                        score=score,
                        server=_as_str(gv.get("server")).strip() or None,
                        primary_entity_type=rule.primary_entity_type,
                        primary_entity_key=primary_key,
                        metrics={
                            "count": agg.count,
                            "unique_alerts": agg.unique_alerts,
                            "unique_servers": agg.unique_servers,
                            "max_severity": agg.max_severity,
                            "sum_severity": agg.sum_severity,
                            "window_seconds": win,
                            "group_key": group_key,
                        },
                        evidence={
                            "rule_id": rule.id,
                            "alert_ids": alert_ids,
                            "group_by": group_by,
                            "group_values": gv,
                            "window_start": agg.first_ts.isoformat(),
                            "window_end": agg.last_ts.isoformat(),
                        },
                        opened_at=agg.first_ts,
                        last_activity_at=agg.last_ts,
                    )
                    db.add(inc)
                    db.flush()
                else:
                    inc.last_activity_at = max(_utc(inc.last_activity_at) or now, agg.last_ts)
                    inc.severity_current = max(int(inc.severity_current or 0), base)
                    inc.score = max(int(inc.score or 0), score)

                    ev = inc.evidence or {}
                    if not isinstance(ev, dict):
                        ev = {}
                    existing = set(int(x) for x in (ev.get("alert_ids") or []) if str(x).isdigit())
                    for aid in alert_ids:
                        existing.add(int(aid))
                    ev["alert_ids"] = sorted(existing)
                    inc.evidence = ev

                    mt = inc.metrics or {}
                    if not isinstance(mt, dict):
                        mt = {}
                    mt["count"] = int(mt.get("count") or 0) + agg.count
                    mt["max_severity"] = max(int(mt.get("max_severity") or 0), agg.max_severity)
                    mt["last_window_end"] = agg.last_ts.isoformat()
                    inc.metrics = mt

                # Vincular alertas al incidente (sin N+1)
                if alert_ids:
                    existing_links = (
                        db.query(IncidentAlert.alert_id)
                        .filter(
                            IncidentAlert.incident_id == inc.id,
                            IncidentAlert.alert_id.in_(alert_ids),
                        )
                        .all()
                    )
                    existing_ids = {int(x[0]) for x in existing_links if x and x[0] is not None}

                    for aid in alert_ids:
                        if int(aid) not in existing_ids:
                            db.add(IncidentAlert(incident_id=inc.id, alert_id=int(aid), role="supporting"))

                state.last_incident_at = now
                db.add(state)

                created_or_updated.append(inc)

        return created_or_updated

