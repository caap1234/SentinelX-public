from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class LogUploadRead(BaseModel):
    id: int
    filename: str
    server: str
    tag: Optional[str] = None
    status: str
    uploaded_at: datetime

    class Config:
        orm_mode = True
