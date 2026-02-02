from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, func
from sqlalchemy.orm import relationship

from app.db import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String(255), nullable=False)
    server = Column(String(255), nullable=False, index=True)

    # Guardamos el hash (HMAC hex) aquí:
    hashed_key = Column(String(255), nullable=False)

    # Estado "operativo"
    is_active = Column(Boolean, nullable=False, default=True)

    # ✅ Estado "definitivo": si es True, NO se debe poder reactivar y NO debe listarse
    is_revoked = Column(Boolean, nullable=False, default=False, index=True)

    # (Opcional pero recomendado) fecha de revocación
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by_user = relationship("User", foreign_keys=[created_by_user_id])

    log_uploads = relationship("LogUpload", back_populates="api_key")
