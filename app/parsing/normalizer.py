# app/parsing/normalizer.py
from __future__ import annotations

from typing import Optional

from app.parsing.registry import parse_line
from app.parsing.types import ParsedEvent


def normalize_line_to_event(
    *,
    source_hint: str,
    line: str,
    server: str,
    log_upload_id: Optional[int] = None,
) -> Optional[ParsedEvent]:
    """
    Entrada única para el pipeline v2:
    Raw line + source_hint -> ParsedEvent (listo para Event ORM)
    """
    return parse_line(
        source_hint=source_hint,
        line=line,
        server=server,
        log_upload_id=log_upload_id,
    )
