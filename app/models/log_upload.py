from __future__ import annotations

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    func,
    Text,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship

from app.db import Base


class LogUpload(Base):
    __tablename__ = "log_uploads"

    id = Column(Integer, primary_key=True, index=True)

    filename = Column(String, nullable=False)
    server = Column(String, nullable=False, index=True)
    tag = Column(String, nullable=True)

    path = Column(String, nullable=False)
    size_bytes = Column(Integer, nullable=False, default=0)

    status = Column(String, nullable=False, default="uploaded", index=True)
    error_message = Column(Text, nullable=True)

    extra_meta = Column(JSON, nullable=True, default=dict)

    uploaded_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    api_key_id = Column(
        Integer,
        ForeignKey("api_keys.id", ondelete="SET NULL"),
        nullable=True,
    )

    uploader_type = Column(String(32), nullable=False, default="user")

    user = relationship("User", back_populates="log_uploads")
    api_key = relationship("ApiKey", back_populates="log_uploads", passive_deletes=True)

    # v2: eventos asociados a este upload
    events = relationship(
        "Event",
        back_populates="log_upload",
        passive_deletes=True,
    )

    __table_args__ = (
        Index("ix_log_uploads_server_uploaded_at", "server", "uploaded_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<LogUpload id={self.id} server={self.server} "
            f"filename={self.filename} status={self.status} uploader_type={self.uploader_type}>"
        )
