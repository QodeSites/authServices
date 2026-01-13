from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from config.settings import settings
from models.models import Base
import logging
import os

logger = logging.getLogger(__name__)

# Database engine configuration
engine_kwargs = {
    "echo": settings.DATABASE_ECHO,
    "pool_pre_ping": True,
    "pool_recycle": 300,
}

def make_sqlite_engine_kwargs():
    return {
        "echo": settings.DATABASE_ECHO,
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "poolclass": StaticPool,
        "connect_args": {"check_same_thread": False},
    }

def is_sqlite_url(url):
    return url.startswith("sqlite")

# Main database
if is_sqlite_url(settings.DATABASE_URL):
    primary_engine_kwargs = make_sqlite_engine_kwargs()
else:
    primary_engine_kwargs = dict(engine_kwargs)
    primary_engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_timeout": 30,
    })

engine = create_engine(settings.DATABASE_URL, **primary_engine_kwargs)

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

# QODEINVEST DB connection
if is_sqlite_url(settings.DB_URL_QODEINVEST):
    qodeinvest_engine_kwargs = make_sqlite_engine_kwargs()
else:
    qodeinvest_engine_kwargs = dict(engine_kwargs)
    qodeinvest_engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_timeout": 30,
    })

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

# QODEPORTFOLIO DB connection
if is_sqlite_url(settings.DB_URL_QODEPORTFOLIO):
    qodeportfolio_engine_kwargs = make_sqlite_engine_kwargs()
else:
    qodeportfolio_engine_kwargs = dict(engine_kwargs)
    qodeportfolio_engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_timeout": 30,
    })

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

# --- Add: FundamentalData and SharePriceData connections using .env paths ---

FUNDAMENTAL_SQLITE_PATH = settings.FUNDAMENTAL_SQLITE_DATA
SHARE_PRICE_SQLITE_PATH = settings.SHARE_PRICE_SQLITE_DATA
INDICATOR_SQLITE_PATH = settings.INDICATOR_SQLITE_DATA
engine_fundamentaldata: Engine = create_engine(
    f"sqlite:///{FUNDAMENTAL_SQLITE_PATH}",
    **make_sqlite_engine_kwargs()
)
SessionLocalFundamentalData = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine_fundamentaldata,
    expire_on_commit=False
)

def get_db_fundamentaldata() -> Session:
    """Dependency to get FundamentalData.db sqlite session"""
    db = SessionLocalFundamentalData()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error (fundamental): {e}")
        db.rollback()
        raise
    finally:
        db.close()

def get_db_session_fundamentaldata() -> Session:
    """Get database session for FundamentalData.db (non-FastAPI usage)"""
    return SessionLocalFundamentalData()

engine_shareprice: Engine = create_engine(
    f"sqlite:///{SHARE_PRICE_SQLITE_PATH}",
    **make_sqlite_engine_kwargs()
)
SessionLocalSharePrice = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine_shareprice,
    expire_on_commit=False
)

def get_db_shareprice() -> Session:
    """Dependency to get SharePriceData.db sqlite session"""
    db = SessionLocalSharePrice()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error (shareprice): {e}")
        db.rollback()
        raise
    finally:
        db.close()

def get_db_session_shareprice() -> Session:
    """Get database session for SharePriceData.db (non-FastAPI usage)"""
    return SessionLocalSharePrice()

engine_indicator: Engine = create_engine(
    f"sqlite:///{INDICATOR_SQLITE_PATH}",
    **make_sqlite_engine_kwargs()
)
SessionLocalIndicator = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine_indicator,
    expire_on_commit=False
)

def get_db_indicator() -> Session:
    """Dependency to get Indicator.db sqlite session"""
    db = SessionLocalIndicator()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error (shareprice): {e}")
        db.rollback()
        raise
    finally:
        db.close()

def get_db_session_indicator() -> Session:
    """Get database session for Indicator.db (non-FastAPI usage)"""
    return SessionLocalIndicator()