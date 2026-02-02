# app/services/log_pipeline.py
from __future__ import annotations

import os
import re
import traceback
import gzip
from datetime import datetime, timezone
from typing import Optional, Dict, Type, Any, IO

from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models.log_upload import LogUpload
from app.models.event import Event
from app.models.raw_log import RawLog

from app.parsing.types import ParsedEvent

from app.parsing.apache_access import ApacheAccessParser
from app.parsing.apache_error_log import ApacheErrorLogParser
from app.parsing.nginx_access import NginxAccessParser
from app.parsing.exim_mainlog import EximMainlogParser
from app.parsing.lfd_log import LfdLogParser
from app.parsing.modsec_audit import ModSecAuditParser
from app.parsing.system_logs import SystemLogParser
from app.parsing.system_secure import SecureLogParser
from app.parsing.cpanel_access import CPanelAccessParser
from app.parsing.panel_logs import PanelLogParser
from app.parsing.wp_error_log import WpErrorLogParser
from app.parsing.sar_stats import SarStatsParser
from app.parsing.maillog_dovecot import MaillogDovecotParser

from app.services.raw_policy import RawPolicy
from app.enrichment.geoip_enricher import enrich_ip_into_extra


# =======================
# Parser registry
# =======================

PARSER_MAP: Dict[str, Type] = {
    "apache_access": ApacheAccessParser,
    "nginx_access": NginxAccessParser,
    "apache_error": ApacheErrorLogParser,
    "exim_mainlog": EximMainlogParser,
    "maillog": MaillogDovecotParser,
    "lfd": LfdLogParser,
    "modsec": ModSecAuditParser,
    "system": SystemLogParser,
    "secure": SecureLogParser,
    "cpanel_access": CPanelAccessParser,
    "panel_logs": PanelLogParser,
    "wp_error_log": WpErrorLogParser,
    "sar": SarStatsParser,
}


# =======================
# Domain / Host helpers
# =======================

DOMLOG_DOMAIN_RE = re.compile(r"^(?P<domain>[^/]+?)(?:-ssl_log|_log)$", re.IGNORECASE)
DA_DOMAIN_LOG_RE = re.compile(r"^(?P<domain>[^/]+?)\.(?:log|error\.log)$", re.IGNORECASE)

REFERER_HOST_RE = re.compile(r"https?://(?P<host>[^/\s\"']+)", re.IGNORECASE)

TRIM_CHARS = " \t\r\n\"'<>[](){}.,;"
HOST_PORT_RE = re.compile(r"^(?P<host>[^:]+):(?P<port>\d{1,5})$")

FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _looks_like_fqdn(value: str) -> bool:
    return bool(value and FQDN_RE.match(value))


def _looks_like_ipv4(value: str) -> bool:
    return bool(value and IPV4_RE.match(value))


def _clean_host(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None

    h = raw.strip().lower().strip(TRIM_CHARS)
    if not h:
        return None

    m = HOST_PORT_RE.match(h)
    if m:
        h = (m.group("host") or "").strip().lower().strip(TRIM_CHARS)

    h = h.strip(TRIM_CHARS)
    if not h:
        return None

    if _looks_like_fqdn(h) or _looks_like_ipv4(h):
        return h
    return None


def _extract_domain_from_file_path(file_path: str) -> Optional[str]:
    base = os.path.basename(file_path or "")
    if not base:
        return None

    m = DOMLOG_DOMAIN_RE.match(base)
    if m:
        return _clean_host(m.group("domain"))

    m = DA_DOMAIN_LOG_RE.match(base)
    if m:
        return _clean_host(m.group("domain"))

    return None


def _extract_host_from_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    m = REFERER_HOST_RE.search(text)
    if not m:
        return None
    return _clean_host(m.group("host"))


def _infer_domain_for_event(*, file_path: str, pe: ParsedEvent, log_type: str) -> Optional[str]:
    web_types = {"apache_access", "nginx_access", "apache_error", "wp_error_log"}
    if log_type not in web_types:
        return None

    d = _extract_domain_from_file_path(file_path)
    if d:
        return d

    extra = pe.extra or {}
    http = extra.get("http") if isinstance(extra, dict) else None

    if isinstance(http, dict):
        d2 = _extract_host_from_text(http.get("referer"))
        if d2:
            return d2

    rh = extra.get("referer_host") if isinstance(extra, dict) else None
    if isinstance(rh, str):
        return _clean_host(rh)

    return None


# =======================
# Pipeline internals
# =======================

def _get_parser(log_type: str):
    cls = PARSER_MAP.get((log_type or "").strip())
    if not cls:
        raise ValueError(f"log_type no soportado: {log_type}")
    return cls()


def _ensure_tz_aware(dt):
    if dt and getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _persist_rawlog(
    db: Session,
    *,
    server: str,
    source_hint: str,
    raw: str,
    log_upload_id: Optional[int],
    line_no: Optional[int],
) -> int:
    rl = RawLog(
        server=server,
        source_hint=source_hint,
        raw=raw,
        log_upload_id=log_upload_id,
        line_no=line_no,
        extra={},
    )
    db.add(rl)
    db.flush()
    return int(rl.id)


def _persist_event(db: Session, pe: ParsedEvent, *, inferred_domain: Optional[str]) -> Event:
    data = pe.to_orm_dict()

    data["timestamp_utc"] = _ensure_tz_aware(data.get("timestamp_utc"))
    data.setdefault("server", "unknown")
    data.setdefault("service", "SYSTEM")
    data.setdefault("source", "unknown")
    data.setdefault("message", "event")
    data.setdefault("extra", {})

    # evita duplicar domain==source
    if isinstance(data.get("domain"), str) and isinstance(pe.source, str):
        if data["domain"].strip().lower() == pe.source.strip().lower():
            data["domain"] = None

    extra = data["extra"]
    if not isinstance(extra, dict):
        extra = {}

    if inferred_domain:
        data["domain"] = inferred_domain
        extra.setdefault("vhost", inferred_domain)

        http = extra.get("http")
        if isinstance(http, dict):
            http.setdefault("host", inferred_domain)

            rh = _extract_host_from_text(http.get("referer"))
            if rh:
                http.setdefault("referer_host", rh)

            extra["http"] = http

    data["extra"] = extra

    # cola engine: por default queda pending (server_default), pero dejamos explícito por claridad
    data.setdefault("engine_status", "pending")
    data["engine_error"] = None  # limpia por si reprocess futuro mete basura

    ev = Event(**data)
    db.add(ev)
    db.flush()
    return ev


def _update_log_meta(
    log: LogUpload,
    *,
    log_type: str,
    file_path: str,
    lines_total: int,
    lines_parsed: int,
    lines_skipped: int,
    lines_failed: int,
    events_created: int,
    raw_saved: int,
    fatal_error: Optional[str] = None,
) -> None:
    meta: Dict[str, Any] = dict(log.extra_meta or {})
    meta.update(
        {
            "pipeline": "v2",
            "log_type": log_type,
            "file_path": file_path,
            "lines_total": lines_total,
            "lines_parsed": lines_parsed,
            "lines_skipped": lines_skipped,
            "lines_failed": lines_failed,
            "events_created": events_created,
            "raw_saved": raw_saved,
        }
    )
    if fatal_error:
        meta["fatal_error"] = fatal_error
    log.extra_meta = meta


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _open_maybe_gzip_text(file_path: str) -> IO[str]:
    fp = (file_path or "").strip()

    if fp.lower().endswith(".gz"):
        return gzip.open(fp, mode="rt", encoding="utf-8", errors="replace")

    try:
        with open(fp, "rb") as fb:
            head = fb.read(2)
        if head == b"\x1f\x8b":
            return gzip.open(fp, mode="rt", encoding="utf-8", errors="replace")
    except Exception:
        pass

    return open(fp, "r", encoding="utf-8", errors="replace")


# =======================
# Main entry (PARSE ONLY)
# =======================

def parse_log_file(file_path: str, server: str, log_type: str, upload_id: int) -> None:
    """
    Parsing-only pipeline:
    - Persist RawLog/Event
    - Enrichment inline opcional
    - NO ejecuta RuleEngine
    - Marca LogUpload: parsing -> parsed (o error)
    """
    db: Session = SessionLocal()
    policy = RawPolicy()

    enrich_inline = (os.getenv("ENRICH_INLINE", "1").strip() not in ("0", "false", "False", ""))

    BATCH_EVENTS = int(os.getenv("PIPELINE_BATCH_EVENTS", "1000").strip() or "1000")
    MAX_LINE_ERRORS = int(os.getenv("PIPELINE_MAX_LINE_ERRORS", "5000").strip() or "5000")

    events_created = raw_saved = 0
    lines_total = lines_parsed = lines_skipped = lines_failed = 0

    try:
        log = db.query(LogUpload).filter(LogUpload.id == upload_id).first()
        if not log:
            return

        # Idempotencia práctica: si ya hay events para este upload, no reparseamos.
        existing = (
            db.query(Event.id)
            .filter(Event.log_upload_id == upload_id)
            .limit(1)
            .first()
        )
        if existing:
            log.status = "parsed"
            meta = dict(log.extra_meta or {})
            meta["parsing_skipped_reason"] = "events_already_exist_for_upload"
            meta["parsing_finished_at"] = _now_iso()
            log.extra_meta = meta
            db.commit()
            return

        log.status = "parsing"
        meta = dict(log.extra_meta or {})
        meta["parsing_started_at"] = _now_iso()
        log.extra_meta = meta
        db.commit()

        parser = _get_parser(log_type)

        with _open_maybe_gzip_text(file_path) as fh:
            for line_no, line in enumerate(fh, start=1):
                lines_total += 1
                raw_line = line.rstrip("\n")
                if not raw_line:
                    lines_skipped += 1
                    continue

                try:
                    with db.begin_nested():
                        pe = parser.parse_line(raw_line, server=server, log_upload_id=upload_id)
                        if not pe:
                            lines_skipped += 1
                            continue

                        inferred_domain = _infer_domain_for_event(file_path=file_path, pe=pe, log_type=log_type)

                        if pe.extra is None:
                            pe.extra = {}

                        if enrich_inline:
                            pe.extra = enrich_ip_into_extra(ip=getattr(pe, "ip_client", None), extra=pe.extra)
                        else:
                            pe.extra.setdefault("enrich_pending", True)

                        decision = policy.decide(log_type=log_type, raw_line=raw_line, pe=pe)
                        if decision.store:
                            pe.raw_id = _persist_rawlog(
                                db,
                                server=server,
                                source_hint=decision.source_hint,
                                raw=raw_line,
                                log_upload_id=upload_id,
                                line_no=line_no,
                            )
                            raw_saved += 1

                        _persist_event(db, pe, inferred_domain=inferred_domain)

                        events_created += 1
                        lines_parsed += 1

                except Exception:
                    lines_failed += 1
                    if lines_failed >= MAX_LINE_ERRORS:
                        raise RuntimeError(f"Too many line errors: {lines_failed}")

                if events_created and (events_created % BATCH_EVENTS == 0):
                    db.commit()

        db.commit()

        log = db.query(LogUpload).filter(LogUpload.id == upload_id).first()
        if log:
            log.status = "parsed"
            log.error_message = None
            _update_log_meta(
                log,
                log_type=log_type,
                file_path=file_path,
                lines_total=lines_total,
                lines_parsed=lines_parsed,
                lines_skipped=lines_skipped,
                lines_failed=lines_failed,
                events_created=events_created,
                raw_saved=raw_saved,
            )
            meta = dict(log.extra_meta or {})
            meta["parsing_finished_at"] = _now_iso()
            log.extra_meta = meta
            db.commit()

    except Exception as e:
        db.rollback()

        log = db.query(LogUpload).filter(LogUpload.id == upload_id).first()
        if log:
            log.status = "error"
            log.error_message = f"{type(e).__name__}: {e}"
            _update_log_meta(
                log,
                log_type=log_type,
                file_path=file_path,
                lines_total=lines_total,
                lines_parsed=lines_parsed,
                lines_skipped=lines_skipped,
                lines_failed=lines_failed,
                events_created=events_created,
                raw_saved=raw_saved,
                fatal_error=f"{type(e).__name__}: {e}",
            )
            meta = dict(log.extra_meta or {})
            meta["parsing_finished_at"] = _now_iso()
            meta["fatal_trace"] = traceback.format_exc()[:8000]
            log.extra_meta = meta
            db.commit()

    finally:
        db.close()


# Backward compat: si algún lugar aún llama process_log_file, que sea parse-only.
def process_log_file(file_path: str, server: str, log_type: str, upload_id: int) -> None:
    parse_log_file(file_path=file_path, server=server, log_type=log_type, upload_id=upload_id)

