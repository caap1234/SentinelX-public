# app/parsing/base.py
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from app.parsing.types import ParsedEvent


class LogParser(ABC):
    source: str

    @abstractmethod
    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        raise NotImplementedError
