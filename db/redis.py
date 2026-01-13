# backend/db/redis.py

import redis
import logging

logger = logging.getLogger(__name__)

# Singleton Redis client
_redis_client: redis.Redis = None


def startup():
    """Initialize Redis connection on app startup"""
    global _redis_client
    try:
        _redis_client = redis.Redis(
            host='localhost',  # Docker exposes to localhost
            port=6379,
            db=0,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        _redis_client.ping()
        logger.info("✅ Redis connected successfully")
    except redis.exceptions.ConnectionError as e:
        logger.warning(f"⚠️ Redis connection failed: {e}. Caching will be disabled.")
        _redis_client = None


def shutdown():
    """Close Redis connection on app shutdown"""
    global _redis_client
    if _redis_client:
        _redis_client.close()
        _redis_client = None
        logger.info("Redis connection closed")


def get_redis_client() -> redis.Redis | None:
    """
    Get the singleton Redis client.
    Returns None if Redis is not available.
    """
    return _redis_client


# Keep for FastAPI Depends compatibility
def get_redis() -> redis.Redis:
    """Dependency for FastAPI routes"""
    if _redis_client is None:
        raise RuntimeError("Redis not initialized")
    return _redis_client