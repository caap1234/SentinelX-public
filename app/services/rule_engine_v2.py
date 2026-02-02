# app/core/rule_engine_v2.py
from __future__ import annotations

import ast
import ipaddress
import json
import os
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.rule_state_v2 import RuleStateV2
from app.models.rule_v2 import RuleV2


EventLike = Union[Event, Dict[str, Any]]


# ----------------------------
# Trust config (+ Lists)
# ----------------------------

def _read_trust_config() -> Dict[str, Any]:
    raw = (os.getenv("SIEM_TRUST_CONFIG_JSON") or "").strip()
    if raw:
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    path = (os.getenv("SIEM_TRUST_CONFIG_PATH") or "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    return {}


_TRUST_CFG: Dict[str, Any] = _read_trust_config()


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _as_str(val: Any) -> str:
    if val is None:
        return ""
    try:
        return str(val)
    except Exception:
        return ""


def _ip_in_cidrs(ip: Optional[str], cidrs: List[str]) -> bool:
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for c in cidrs:
        c = (c or "").strip()
        if not c:
            continue
        try:
            if "/" in c:
                net = ipaddress.ip_network(c, strict=False)
                if ip_obj in net:
                    return True
            else:
                if ip_obj == ipaddress.ip_address(c):
                    return True
        except ValueError:
            continue
    return False


def _is_non_global_ip(ip: Optional[str]) -> bool:
    """
    True si la IP NO es enrutable globalmente (loopback, RFC1918, link-local, reserved, etc.)
    Esto evita falsos positivos de GEO (ej. country_code=PRV).
    """
    if not ip:
        return False
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    try:
        return not bool(obj.is_global)
    except Exception:
        return bool(
            getattr(obj, "is_private", False)
            or getattr(obj, "is_loopback", False)
            or getattr(obj, "is_link_local", False)
            or getattr(obj, "is_reserved", False)
            or getattr(obj, "is_unspecified", False)
        )


def _get_trusted_countries() -> List[str]:
    return [str(x).strip().upper() for x in _as_list(_TRUST_CFG.get("trusted_countries")) if str(x).strip()]


def _get_trusted_ips_global() -> List[str]:
    return [str(x).strip() for x in _as_list(_TRUST_CFG.get("trusted_ips")) if str(x).strip()]


def _get_trusted_server_ips(server: Optional[str]) -> List[str]:
    if not server:
        return []
    servers = _TRUST_CFG.get("servers")
    if not isinstance(servers, dict):
        return []
    entry = servers.get(server)
    if not isinstance(entry, dict):
        return []
    ips = entry.get("server_ips")
    return [str(x).strip() for x in _as_list(ips) if str(x).strip()]


# ✅ NUEVO: ASN confiables (global)
def _get_trusted_asn_numbers() -> List[int]:
    out: List[int] = []
    for x in _as_list(_TRUST_CFG.get("trusted_asn_numbers")):
        try:
            if x is None:
                continue
            out.append(int(str(x).strip()))
        except Exception:
            continue
    return out


def _get_event_asn_number(event: EventLike) -> Optional[int]:
    v = _get_from_event(event, "extra.asn.number")
    if v is None:
        v = _get_from_event(event, "extra.asn_number")  # por si algún parser lo deja plano
    try:
        if v is None:
            return None
        return int(str(v).strip())
    except Exception:
        return None


def _event_snapshot(event: Event) -> Dict[str, Any]:
    """
    Congela lo necesario del evento para evitar lazy-load/expired attributes
    durante el procesamiento del engine (trabaja con dict, no ORM "vivo").
    """
    extra = event.extra if isinstance(event.extra, dict) else {}
    return {
        "id": event.id,
        "raw_id": getattr(event, "raw_id", None),
        "source": getattr(event, "source", None),
        "server": getattr(event, "server", None),
        "ip_client": getattr(event, "ip_client", None),
        "username": getattr(event, "username", None),
        "timestamp_utc": getattr(event, "timestamp_utc", None),
        "extra": extra,
    }


def _is_trusted_event(*, event: EventLike, geo_country: Optional[str]) -> bool:
    ip_client = _get_from_event(event, "ip_client")
    server = _get_from_event(event, "server")

    if _is_non_global_ip(_as_str(ip_client).strip() or None):
        return True

    trusted_countries = _get_trusted_countries()
    if geo_country and geo_country.upper() in trusted_countries:
        return True

    # ✅ NUEVO: Trust por ASN
    asn_num = _get_event_asn_number(event)
    if asn_num is not None and asn_num in _get_trusted_asn_numbers():
        return True

    if _ip_in_cidrs(_as_str(ip_client).strip() or None, _get_trusted_ips_global()):
        return True

    if _ip_in_cidrs(_as_str(ip_client).strip() or None, _get_trusted_server_ips(_as_str(server).strip() or None)):
        return True

    return False


# ----------------------------
# Per-rule trust overrides (emit.*)
# ----------------------------

def _get_trusted_countries_extra(rule_emit: Any) -> List[str]:
    if not isinstance(rule_emit, dict):
        return []
    return [str(x).strip().upper() for x in _as_list(rule_emit.get("trusted_countries_extra")) if str(x).strip()]


def _get_trusted_ips_extra(rule_emit: Any) -> List[str]:
    if not isinstance(rule_emit, dict):
        return []
    return [str(x).strip() for x in _as_list(rule_emit.get("trusted_ips_extra")) if str(x).strip()]


def _get_trusted_usernames_extra(rule_emit: Any) -> List[str]:
    if not isinstance(rule_emit, dict):
        return []
    return [str(x).strip().lower() for x in _as_list(rule_emit.get("trusted_usernames_extra")) if str(x).strip()]


def _is_trusted_event_for_rule(*, event: EventLike, geo_country: Optional[str], rule_emit: Any) -> bool:
    if _is_trusted_event(event=event, geo_country=geo_country):
        return True

    if geo_country and geo_country.upper() in _get_trusted_countries_extra(rule_emit):
        return True

    ip_client = _as_str(_get_from_event(event, "ip_client")).strip() or None
    if _ip_in_cidrs(ip_client, _get_trusted_ips_extra(rule_emit)):
        return True

    username = _as_str(_get_from_event(event, "username")).strip().lower()
    if username and username in _get_trusted_usernames_extra(rule_emit):
        return True

    return False


# ----------------------------
# Lists config
# ----------------------------

def _get_lists_root() -> Dict[str, Any]:
    lists = _TRUST_CFG.get("lists")
    return lists if isinstance(lists, dict) else {}


def _get_list(name: Optional[str]) -> List[str]:
    if not name:
        return []
    root = _get_lists_root()
    v = root.get(name)
    out: List[str] = []
    for x in _as_list(v):
        s = _as_str(x).strip()
        if s:
            out.append(s)
    return out


# ----------------------------
# Safe expression evaluation
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
    code = compile(tree, "<rule_condition>", "eval")
    return bool(eval(code, {"__builtins__": {}}, {**_ALLOWED_NAMES, **ctx}))


# ----------------------------
# Helpers
# ----------------------------

def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _norm_source(v: Optional[str]) -> str:
    return (v or "").strip().upper()


def _norm_event_type(v: Optional[str]) -> str:
    return (v or "").strip().lower()


def _ip_subnet(ip: Optional[str], prefix: int = 24) -> Optional[str]:
    if not ip:
        return None
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if obj.version != 4:
        return None
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return f"{net.network_address}/{prefix}"
    except Exception:
        return None


def _get_from_event(event: EventLike, path: str) -> Any:
    if not path:
        return None

    if path == "ip_subnet24":
        return _ip_subnet(_as_str(_get_from_event(event, "ip_client")).strip() or None, 24)
    if path == "ip_subnet16":
        return _ip_subnet(_as_str(_get_from_event(event, "ip_client")).strip() or None, 16)

    parts = path.split(".")
    cur: Any = event
    for p in parts:
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif hasattr(cur, p):
            cur = getattr(cur, p)
        else:
            return None
    return cur


def _to_number(v: Any) -> Optional[float]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        s = str(v).strip()
        if not s:
            return None
        return float(s)
    except Exception:
        return None


def _coerce_scalar(val: Any) -> Any:
    if val is None:
        return None
    if isinstance(val, (bool, int, float)):
        return val
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return ""
        sl = s.lower()
        if sl in ("true", "false"):
            return sl == "true"
        n = _to_number(s)
        if n is not None:
            if abs(n - int(n)) < 1e-9:
                return int(n)
            return n
        return s
    return val


def _resolve_let_block(event: EventLike, let_block: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not isinstance(let_block, dict):
        return out

    for k, v in let_block.items():
        key = _as_str(k).strip()
        if not key:
            continue

        if isinstance(v, str):
            vv = v.strip()
            if vv:
                if "." in vv or vv.startswith("extra") or vv in ("server", "ip_client", "username", "ip_subnet24", "ip_subnet16"):
                    out[key] = _coerce_scalar(_get_from_event(event, vv))
                else:
                    out[key] = _coerce_scalar(vv)
            else:
                out[key] = None
        else:
            out[key] = _coerce_scalar(v)

    return out


def _match_rule(event: EventLike, rule: RuleV2) -> bool:
    m = rule.match or {}
    if not isinstance(m, dict) or not m:
        return True

    for field, cond in m.items():
        val = _get_from_event(event, field)

        if isinstance(cond, dict):
            if "exists" in cond:
                want = bool(cond["exists"])
                if want != (val is not None):
                    return False

            if "eq" in cond:
                if val != cond["eq"]:
                    return False

            if "contains" in cond:
                needle = _as_str(cond["contains"])
                hay = _as_str(val)
                if needle not in hay:
                    return False

            if "contains_any" in cond or "contains_any_ref" in cond:
                arr = cond.get("contains_any")
                if "contains_any_ref" in cond:
                    arr = _get_list(_as_str(cond.get("contains_any_ref")).strip())

                if not isinstance(arr, list) or not arr:
                    return False

                hay = _as_str(val)
                if not any((_as_str(x) != "") and (_as_str(x) in hay) for x in arr):
                    return False

            for key in (">=", ">", "<=", "<"):
                if key in cond:
                    try:
                        fval = float(val)
                        fcmp = float(cond[key])
                    except Exception:
                        return False
                    if key == ">=" and not (fval >= fcmp):
                        return False
                    if key == ">" and not (fval > fcmp):
                        return False
                    if key == "<=" and not (fval <= fcmp):
                        return False
                    if key == "<" and not (fval < fcmp):
                        return False

            if "in" in cond or "in_ref" in cond:
                arr = cond.get("in")
                if "in_ref" in cond:
                    arr = _get_list(_as_str(cond.get("in_ref")).strip())

                if not isinstance(arr, list) or not arr:
                    return False
                if val not in arr:
                    return False
        else:
            if val != cond:
                return False

    return True


def _build_group_key(event: EventLike, group_by: List[str]) -> str:
    parts: List[str] = []
    for f in group_by:
        v = _get_from_event(event, f)
        parts.append(str(v) if v is not None else "-")
    return "|".join(parts)


def _extract_action_for_window(extra: Any) -> Optional[str]:
    if not isinstance(extra, dict):
        return None

    a = _as_str(extra.get("action")).strip().lower()
    if a in ("fail", "failed"):
        return "fail"
    if a in ("success", "ok", "passed"):
        return "success"

    if extra.get("event_type") == "auth_login":
        a2 = _as_str(extra.get("action")).strip().lower()
        if a2 in ("fail", "failed"):
            return "fail"
        if a2 in ("success", "ok"):
            return "success"

    panel = extra.get("panel")
    if isinstance(panel, dict):
        st = _as_str(panel.get("status")).strip().lower()
        if st in ("failed", "fail"):
            return "fail"
        if st in ("ok", "success"):
            return "success"

    return None


def _extract_path_for_window(event: EventLike) -> Optional[str]:
    p = _get_from_event(event, "extra.http.path")
    if p is not None:
        s = _as_str(p).strip()
        return s or None

    p = _get_from_event(event, "extra.panel.path")
    if p is not None:
        s = _as_str(p).strip()
        return s or None

    p = _get_from_event(event, "extra.waf.uri")
    if p is not None:
        s = _as_str(p).strip()
        return s or None

    return None


def _get_or_create_rule_state_locked(db: Session, *, rule_id: int, group_key: str) -> RuleStateV2:
    """
    Evita deadlocks:
      - lock del row existente (FOR UPDATE)
      - si no existe: INSERT idempotente con ON CONFLICT DO NOTHING (requiere UNIQUE(rule_id, group_key))
      - lock de nuevo

    Importante: asume transacción activa.
    """
    st = (
        db.query(RuleStateV2)
        .filter(RuleStateV2.rule_id == rule_id, RuleStateV2.group_key == group_key)
        .with_for_update()
        .first()
    )
    if st:
        return st

    try:
        db.execute(
            text(
                """
                INSERT INTO rule_states_v2 (rule_id, group_key, last_seen_at, last_alert_at, extra)
                VALUES (:rule_id, :group_key, NULL, NULL, '{}'::jsonb)
                ON CONFLICT (rule_id, group_key) DO NOTHING
                """
            ),
            {"rule_id": int(rule_id), "group_key": str(group_key)},
        )
    except IntegrityError:
        # carrera normal: otro worker insertó primero
        pass

    st2 = (
        db.query(RuleStateV2)
        .filter(RuleStateV2.rule_id == rule_id, RuleStateV2.group_key == group_key)
        .with_for_update()
        .first()
    )
    if st2:
        return st2

    raise RuntimeError(f"Unable to get or create RuleStateV2 for rule_id={rule_id} group_key={group_key}")


@dataclass
class _BufItem:
    ts: datetime
    event_id: Any  # UUID
    raw_id: Optional[int]
    server: Optional[str] = None
    path: Optional[str] = None
    ip_client: Optional[str] = None
    ip_subnet24: Optional[str] = None
    username: Optional[str] = None
    action: Optional[str] = None  # fail/success


class RuleEngineV2:
    def __init__(self) -> None:
        self._index: Dict[Tuple[str, str], List[RuleV2]] = {}
        self._windows: Dict[Tuple[int, str], Deque[_BufItem]] = defaultdict(deque)

        # Auto-reload (evita engine vacío si el proceso arrancó antes de cargar reglas)
        self._last_reload_at: Optional[datetime] = None
        self._reload_ttl_seconds: int = int(os.getenv("RULE_ENGINE_RELOAD_TTL_SECONDS", "60").strip() or "60")

    def reload_rules(self, db: Session) -> None:
        rules = (
            db.query(RuleV2)
            .filter(RuleV2.enabled.is_(True))
            .all()
        )

        idx: Dict[Tuple[str, str], List[RuleV2]] = defaultdict(list)
        for r in rules:
            src = _norm_source(r.source)
            et = _norm_event_type(r.event_type)
            idx[(src, et)].append(r)

        # Orden determinístico por id (reduce variaciones multi-worker)
        for k in list(idx.keys()):
            idx[k] = sorted(idx[k], key=lambda rr: int(rr.id))

        self._index = dict(idx)
        self._last_reload_at = datetime.now(timezone.utc)

    def _maybe_reload(self, db: Session) -> None:
        now = datetime.now(timezone.utc)
        if not self._index:
            self.reload_rules(db)
            return
        if self._last_reload_at is None:
            self.reload_rules(db)
            return
        if (now - self._last_reload_at).total_seconds() >= float(self._reload_ttl_seconds):
            self.reload_rules(db)

    def on_event(self, db: Session, event: Event) -> List[Alert]:
        # Asegura index cargado/actualizado (TTL)
        self._maybe_reload(db)

        alerts: List[Alert] = []
        snap = _event_snapshot(event)

        src = _norm_source(_as_str(_get_from_event(snap, "source")) or None)

        ev_extra = _get_from_event(snap, "extra") or {}
        extra = ev_extra if isinstance(ev_extra, dict) else {}
        et = _norm_event_type(_as_str(extra.get("event_type")))

        if not src or not et:
            return alerts

        candidates = self._index.get((src, et), [])
        if not candidates:
            return alerts

        candidates = sorted(candidates, key=lambda rr: int(rr.id))

        ev_ts = _utc(_get_from_event(snap, "timestamp_utc")) or datetime.now(timezone.utc)

        geo = extra.get("geo")
        if not isinstance(geo, dict) or not geo:
            geo = extra.get("geoip")
        if not isinstance(geo, dict):
            geo = None

        asn = extra.get("asn") if isinstance(extra.get("asn"), dict) else None
        geo_country = geo.get("country_code") if isinstance(geo, dict) else None

        ev_ip = _as_str(_get_from_event(snap, "ip_client")).strip() or None
        ev_user = _as_str(_get_from_event(snap, "username")).strip() or None
        ev_server = _as_str(_get_from_event(snap, "server")).strip() or None
        ev_action = _extract_action_for_window(extra)
        ev_subnet24 = _ip_subnet(ev_ip, 24)

        for rule in candidates:
            rule_emit = rule.emit or {}
            ignore_trust = bool(rule_emit.get("ignore_trust"))

            is_trusted_eff = _is_trusted_event_for_rule(event=snap, geo_country=geo_country, rule_emit=rule_emit)
            if is_trusted_eff and not ignore_trust:
                continue

            if not _match_rule(snap, rule):
                continue

            gb = list(rule.group_by or [])
            if not gb:
                gb = ["server"]
            group_key = _build_group_key(snap, gb)

            win_key = (int(rule.id), group_key)
            dq = self._windows[win_key]

            dq.append(
                _BufItem(
                    ts=ev_ts,
                    event_id=_get_from_event(snap, "id"),
                    raw_id=_get_from_event(snap, "raw_id"),
                    server=ev_server,
                    path=_extract_path_for_window(snap),
                    ip_client=ev_ip,
                    ip_subnet24=ev_subnet24,
                    username=ev_user.lower() if ev_user else None,
                    action=ev_action,
                )
            )

            win_sec = int(rule.window_seconds or 300)
            cutoff = ev_ts - timedelta(seconds=win_sec)
            while dq and dq[0].ts < cutoff:
                dq.popleft()

            path_set: set[str] = set()
            ip_set: set[str] = set()
            user_set: set[str] = set()
            server_set: set[str] = set()
            subnet24_set: set[str] = set()

            subnet24_counts: Dict[str, int] = defaultdict(int)

            fail_count = 0
            success_count = 0

            for it in dq:
                if it.path:
                    path_set.add(it.path)
                if it.ip_client:
                    ip_set.add(it.ip_client)
                if it.username:
                    user_set.add(it.username)
                if it.server:
                    server_set.add(it.server)

                if it.ip_subnet24:
                    subnet24_set.add(it.ip_subnet24)
                    subnet24_counts[it.ip_subnet24] += 1

                if it.action == "fail":
                    fail_count += 1
                elif it.action == "success":
                    success_count += 1

            unique_paths = len(path_set)
            unique_ips = len(ip_set)
            unique_users = len(user_set)
            unique_servers = len(server_set)
            unique_subnets24 = len(subnet24_set)

            top_subnet24: Optional[str] = None
            top_subnet24_hits = 0
            if subnet24_counts:
                top_subnet24, top_subnet24_hits = max(subnet24_counts.items(), key=lambda kv: kv[1])

            ctx: Dict[str, Any] = {
                "count": len(dq),
                "unique_paths": unique_paths,
                "unique_ips": unique_ips,
                "unique_users": unique_users,
                "unique_servers": unique_servers,
                "unique_subnets24": unique_subnets24,
                "top_subnet24_hits": top_subnet24_hits,
                "top_subnet24": top_subnet24,
                "fail_count": fail_count,
                "success_count": success_count,
                "server": _get_from_event(snap, "server"),
                "source": src,
                "event_type": et,
                "group_key": group_key,
                "ip_client": _get_from_event(snap, "ip_client"),
                "ip_subnet24": ev_subnet24,
                "username": _get_from_event(snap, "username"),
            }

            if isinstance(geo, dict):
                ctx["geo_country"] = geo_country
            if isinstance(asn, dict):
                ctx["asn_number"] = asn.get("number")

            try:
                let_block = getattr(rule, "let", None)
            except Exception:
                let_block = None
            ctx.update(_resolve_let_block(snap, let_block))

            cooldown = int(rule.cooldown_seconds or 0)

            # CLAVE anti-deadlock
            state = _get_or_create_rule_state_locked(db, rule_id=int(rule.id), group_key=group_key)
            state.last_seen_at = ev_ts

            if cooldown > 0 and state.last_alert_at:
                if ev_ts < _utc(state.last_alert_at) + timedelta(seconds=cooldown):
                    db.add(state)
                    continue

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

            evidence_cfg = rule.evidence or {}
            n = int(evidence_cfg.get("last_n", 10))

            last_items = list(dq)[-n:]
            evidence_ids = [x.event_id for x in last_items if x.event_id is not None]

            raw_samples: List[str] = []
            if evidence_cfg.get("include_raw", True) and evidence_ids:
                evs = db.query(Event.id, Event.raw_id).filter(Event.id.in_(evidence_ids)).all()
                raw_ids = [e.raw_id for e in evs if e.raw_id is not None]
                if raw_ids:
                    from app.models.raw_log import RawLog
                    rows = db.query(RawLog.id, RawLog.raw).filter(RawLog.id.in_(raw_ids)).all()
                    raw_by_id = {r.id: r.raw for r in rows}
                    for e in evs:
                        if e.raw_id in raw_by_id:
                            raw_samples.append((raw_by_id[e.raw_id] or "")[:500])

            group_values: Dict[str, Any] = {}
            group_values["server"] = _get_from_event(snap, "server")
            group_values["ip_client"] = _get_from_event(snap, "ip_client")
            group_values["username"] = _get_from_event(snap, "username")

            for f in gb:
                ff = _as_str(f).strip()
                if not ff:
                    continue
                if ff in group_values:
                    continue
                try:
                    group_values[ff] = _get_from_event(snap, ff)
                except Exception:
                    group_values[ff] = None

            try:
                group_values["extra.vhost"] = _get_from_event(snap, "extra.vhost")
                group_values["extra.geo.country_code"] = _get_from_event(snap, "extra.geo.country_code")
                group_values["extra.asn.number"] = _get_from_event(snap, "extra.asn.number")
                group_values["extra.asn.org"] = _get_from_event(snap, "extra.asn.org")
            except Exception:
                pass

            al = Alert(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=int(rule.severity or 3),
                server=_get_from_event(snap, "server"),
                source=src,
                event_type=et,
                group_key=group_key,
                triggered_at=ev_ts,
                window_start=cutoff,
                window_end=ev_ts,
                metrics={
                    "count": len(dq),
                    "unique_paths": unique_paths,
                    "unique_ips": unique_ips,
                    "unique_users": unique_users,
                    "unique_servers": unique_servers,
                    "unique_subnets24": unique_subnets24,
                    "top_subnet24": top_subnet24,
                    "top_subnet24_hits": top_subnet24_hits,
                    "fail_count": fail_count,
                    "success_count": success_count,
                    "window_seconds": win_sec,
                    "trusted": is_trusted_eff,
                },
                evidence={
                    "event_ids": [str(x) for x in evidence_ids],
                    "raw_samples": raw_samples,
                    "group_by": gb,
                    "group_values": group_values,
                },
                status="open",
            )
            db.add(al)

            state.last_alert_at = ev_ts
            db.add(state)

            alerts.append(al)

        return alerts

