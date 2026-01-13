from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from .settings import settings

# Sync database
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    echo=settings.DEBUG
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Async database (if needed for high-performance endpoints)
if settings.DATABASE_ASYNC_URL:
    async_engine = create_async_engine(
        settings.DATABASE_ASYNC_URL,
        pool_pre_ping=True,
        pool_recycle=300,
        echo=settings.DEBUG
    )
    AsyncSessionLocal = sessionmaker(
        async_engine, 
        class_=AsyncSession, 
        expire_on_commit=False
    )

Base = declarative_base()