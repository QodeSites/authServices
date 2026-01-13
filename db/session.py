from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from config.settings import settings
from models.models import Base
import logging
import os

logger = logging.getLogger(__name__)

# Database engine configuration (No SQLite)
engine_kwargs = {
    "echo": settings.DATABASE_ECHO,
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "pool_size": 10,
    "max_overflow": 20,
    "pool_timeout": 30,
}

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False
)

def create_tables():
    """Create all database tables"""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
        raise

def get_db() -> Session:
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def get_db_session() -> Session:
    """Get database session for non-FastAPI usage"""
    return SessionLocal()

# QODEINVEST DB connection (No SQLite option)
qodeinvest_engine_kwargs = dict(engine_kwargs)
engine_qodeinvest: Engine = create_engine(settings.DB_URL_QODEINVEST, **qodeinvest_engine_kwargs)
SessionLocalQodeInvest = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine_qodeinvest,
    expire_on_commit=False
)

def get_db_qodeinvest() -> Session:
    """Dependency to get database session"""
    db = SessionLocalQodeInvest()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def get_db_session_qodeinvest() -> Session:
    """Get database session for non-FastAPI usage"""
    return SessionLocalQodeInvest()

# QODEPORTFOLIO DB connection (No SQLite option)
qodeportfolio_engine_kwargs = dict(engine_kwargs)
engine_qode_portfolio: Engine = create_engine(settings.DB_URL_QODEPORTFOLIO, **qodeportfolio_engine_kwargs)
SessionLocalQodePortfolio = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine_qode_portfolio,
    expire_on_commit=False
)

def get_db_qode_portfolio() -> Session:
    """Dependency to get database session"""
    db = SessionLocalQodePortfolio()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def get_db_session_qode_portfolio() -> Session:
    """Get database session for non-FastAPI usage"""
    return SessionLocalQodePortfolio()
