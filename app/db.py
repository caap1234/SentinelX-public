from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from .config import settings

# Engine de SQLAlchemy
engine = create_engine(
    settings.DATABASE_URL,
    future=True,
    echo=False,  # pon True si quieres ver el SQL en consola
    pool_pre_ping=True,
)

# Factoría de sesiones
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,  # <- evita expirar instancias ORM tras commit (clave para engine cache)
)

# Base para los modelos ORM
Base = declarative_base()


# Dependencia para usar en FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
