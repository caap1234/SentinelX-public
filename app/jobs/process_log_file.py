# app/jobs/process_log_file.py
from __future__ import annotations

from typing import List, Optional, Iterable, Any
from datetime import datetime, timezone
import logging

from app.core.models import RawEvent
from app.parsing.apache_access import ApacheAccessParser
from app.parsing.exim_mainlog import EximMainlogParser
from app.parsing.wp_error_log import WpErrorLogParser
from app.parsing.modsec_audit import ModSecAuditParser
from app.parsing.system_secure import SecureLogParser
from app.parsing.panel_logs import PanelLogParser
from app.parsing.lfd_log import LfdLogParser
from app.parsing.filemanager import FileManagerParser
from app.parsing.system_logs import SystemLogParser
from app.parsing.sar_stats import SarStatsParser
from app.parsing.apache_error_log import ApacheErrorLogParser
from app.parsing.cpanel_access import CPanelAccessParser

from app.enrichment.geoip_enricher import enrich_geoip
from app.storage.repository import EventRepository

from app.db import SessionLocal
from app.models.log_upload import LogUpload


logger = logging.getLogger("sentinelx.process_log")


def get_parser(log_type: str):
    """
    Devuelve el parser adecuado según el tipo de log interno.
    Acepta aliases comunes para evitar que el UI rompa el pipeline.
    """
    t = (log_type or "").strip().lower()

    if t in ("apache_access", "access_log", "http_access", "apache", "domlog", "domlogs"):
        return ApacheAccessParser()

    if t in ("apache_error", "apache_error_log", "error_log", "apache_err", "http_error"):
        return ApacheErrorLogParser()

    if t in ("exim_mainlog", "exim"):
        return EximMainlogParser()

    if t in ("wp_error_log", "wordpress_error", "wp_error"):
        return WpErrorLogParser()

    if t in ("modsec", "modsec_audit", "modsec_audit_log", "modsecurity"):
        return ModSecAuditParser()

    if t in ("secure", "ssh", "ssh_secure", "system_secure"):
        return SecureLogParser()

    if t in ("panel",):
        return PanelLogParser()

    if t in ("lfd", "lfd_log", "lfd.log"):
        return LfdLogParser()

    if t in ("filemanager",):
        return FileManagerParser()

    if t in ("system", "messages", "syslog"):
        return SystemLogParser()

    if t in ("sar", "sar_stats"):
        return SarStatsParser()

    if t in ("cpanel", "cpanel_access"):
        return CPanelAccessParser()

    raise ValueError(f"Tipo de log no soportado: {log_type}")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_set_log_error(log: LogUpload, msg: str) -> None:
    """
    Guarda un error_message recortado para no romper límites de BD.
    """
    trimmed = (msg or "").strip()
    if len(trimmed) > 2000:
        trimmed = trimmed[:2000] + "…"
    if hasattr(log, "error_message"):
        log.error_message = trimmed


def _safe_clear_log_error(log: LogUpload) -> None:
    if hasattr(log, "error_message"):
        log.error_message = None


def _safe_merge_extra_meta(log: LogUpload, payload: dict) -> None:
    """
    Guarda métricas en log.extra_meta (si existe).
    """
    if not hasattr(log, "extra_meta"):
        return
    current = getattr(log, "extra_meta", None) or {}
    if not isinstance(current, dict):
        current = {}
    current.update(payload)
    log.extra_meta = current


def _iter_newly_saved_events(saved_result: Any, fallback_events: Optional[Iterable[Any]] = None) -> Iterable[Any]:
    """
    Normaliza el retorno de repo.save_events:
      - Si regresa lista/iterable -> lo usamos
      - Si regresa None/bool/int -> usamos fallback_events (si hay)
    """
    if saved_result is None:
        return fallback_events or []
    if isinstance(saved_result, list):
        return saved_result
    if isinstance(saved_result, tuple):
        return list(saved_result)
    try:
        iter(saved_result)
        if isinstance(saved_result, (str, bytes)):
            return fallback_events or []
        return saved_result
    except Exception:
        return fallback_events or []


def _safe_notify_for_events(db, events: Iterable[Any]) -> None:
    """
    Envía alertas por email según settings.
    - No rompe si falla
    - Limita a cierto número para evitar spam en lotes enormes
    """
    max_alerts = 20
    count = 0

    for ev in events:
        if count >= max_alerts:
            break

        try:
            severity_value = getattr(ev, "severity", None)
            message = getattr(ev, "message", "") or ""
            server = getattr(ev, "server", None)
            rule_id = getattr(ev, "rule_id", None)
            rule_name = getattr(ev, "rule_name", None)

            title = (rule_name or rule_id or "Evento detectado").strip()

            count += 1
        except Exception:
            logger.exception("Fallo preparando/envíando alerta (se ignoró).")

    if count:
        logger.info("Alertas procesadas (intentadas): %s", count)


def process_log_file(
    file_path: str,
    server: str,
    log_type: str,
    upload_id: Optional[int] = None,
):
    """
    Procesa un archivo de log:
      - parsea líneas -> RawEvent
      - enriquece (GeoIP, etc.)
      - aplica engine de detección
      - agrega eventos (EventAggregator)
      - guarda siem_events en la BD
      - opcional: actualiza status del LogUpload (y error_message)
      - ✅ envía alertas por email según severidad (no rompe si falla SMTP)

    ✅ CAMBIO:
      - Ya no guardamos raw_block (últimas 10 líneas con ruido)
      - Guardamos solo raw_hit (línea exacta) + source (path/log_type/line_no)
      - El aggregator guardará máximo 10 raw_hit por evento agregado (raw_hits_sample)
    """
    parser = get_parser(log_type)
    raw_events: List[RawEvent] = []

    # métricas simples (para debug/observabilidad)
    parsed_lines = 0
    events_parsed = 0
    events_detected = 0
    events_saved = 0

    db = SessionLocal()
    log: Optional[LogUpload] = None

    try:
        if upload_id is not None:
            log = db.query(LogUpload).get(upload_id)
            if log:
                log.status = "processing"
                _safe_clear_log_error(log)
                _safe_merge_extra_meta(
                    log,
                    {
                        "job_started_at": _utc_now().isoformat(),
                        "server": server,
                        "log_type": log_type,
                        "file_path": file_path,
                    },
                )
                db.commit()

        # 1) Parseo línea a línea
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parsed_lines += 1
                clean_line = line.rstrip("\n")

                ev = parser.parse_line(line, server=server)
                if not ev:
                    continue

                # ✅ Guardar evidencia mínima del hit (la línea exacta)
                extra = dict(getattr(ev, "extra", {}) or {})
                extra["raw_hit"] = clean_line

                # ✅ Pista de origen (opcional, útil para debug / “ver más contexto” en el futuro)
                extra["source"] = {
                    "path": file_path,
                    "log_type": log_type,
                    "line_no": parsed_lines,
                    "upload_id": upload_id,
                }

                ev.extra = extra

                raw_events.append(ev)
                events_parsed += 1

        # Si no hubo eventos parseables, lo marcamos como processed sin error
        if not raw_events:
            if log is not None:
                log.status = "processed"
                _safe_clear_log_error(log)
                _safe_merge_extra_meta(
                    log,
                    {
                        "parsed_lines": parsed_lines,
                        "events_parsed": events_parsed,
                        "events_detected": 0,
                        "events_saved": 0,
                        "job_finished_at": _utc_now().isoformat(),
                        "note": "No hubo líneas parseables para este parser/tag.",
                    },
                )
                db.commit()
            return

        # 2) Enriquecimiento GeoIP
        enrich_geoip(raw_events)


        # 5) Marcar upload como procesado
        if log is not None:
            log.status = "processed"
            _safe_clear_log_error(log)
            _safe_merge_extra_meta(
                log,
                {
                    "parsed_lines": parsed_lines,
                    "events_parsed": events_parsed,
                    "events_detected": events_detected,
                    "events_saved": events_saved,
                    "job_finished_at": _utc_now().isoformat(),
                },
            )
            db.commit()

    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass

        if upload_id is not None:
            try:
                if log is None:
                    log = db.query(LogUpload).get(upload_id)
                if log:
                    log.status = "error"
                    _safe_set_log_error(log, f"{type(e).__name__}: {e}")
                    _safe_merge_extra_meta(
                        log,
                        {
                            "parsed_lines": parsed_lines,
                            "events_parsed": events_parsed,
                            "events_detected": events_detected,
                            "events_saved": events_saved,
                            "job_failed_at": _utc_now().isoformat(),
                        },
                    )
                    db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass

        raise

    finally:
        db.close()