"""
Auth-service smoke tests (Agent 9 / Phase 6).

These tests do NOT spin up the database, Redis, or a real ASGI server. They
import `main.app` (with required env vars stubbed in by the test fixture)
and assert structural invariants:

  - `app` is a FastAPI instance.
  - `settings.JWT_SECRET` falls back to `SECRET_KEY` and vice versa
    (the Agent 6 security fix that removed the random-default behaviour).
  - The OTP service URL is read from the environment (TWO_FACTOR_API_URL).
  - The lifespan startup raises if JWT_SECRET / SECRET_KEY are *both* missing
    (the production safety net).

Run from `authServices/`:
    pytest tests/
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest


_AUTH_SVC_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _stub_env(monkeypatch):
    """Stub the env vars `Settings()` requires so the import succeeds."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://stub@localhost/stub")
    monkeypatch.setenv("DB_URL_QODEINVEST", "postgresql://stub@localhost/stub")
    monkeypatch.setenv("DB_URL_QODEPORTFOLIO", "postgresql://stub@localhost/stub")
    monkeypatch.setenv("JWT_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----")
    monkeypatch.setenv("JWT_PUBLIC_KEY", "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----")
    monkeypatch.setenv("ADMIN_AUTH_ID", "stub-admin")
    monkeypatch.setenv("JWT_SECRET", "stub-jwt-secret")
    monkeypatch.setenv("TWO_FACTOR_API_KEY", "stub-key")
    monkeypatch.setenv("TWO_FACTOR_API_URL", "https://example.invalid/v1")
    # Make `from config.settings import settings` work — auth service expects
    # the working directory to be `authServices/`. When pytest runs from the
    # repo root, the module path differs; we rely on the `cwd-relative` import
    # used in the existing codebase.
    if str(_AUTH_SVC_ROOT) not in sys.path:
        sys.path.insert(0, str(_AUTH_SVC_ROOT))
    # Ensure a clean import each test (settings is module-level singleton).
    for mod_name in [m for m in sys.modules if m.startswith(("config", "main"))]:
        sys.modules.pop(mod_name, None)
    yield


def test_settings_load_with_jwt_secret():
    """Settings loads cleanly when env is fully populated."""
    from config.settings import settings

    assert settings.JWT_SECRET == "stub-jwt-secret"
    # Mirror logic should populate SECRET_KEY from JWT_SECRET (Agent 6 fix).
    assert settings.SECRET_KEY == "stub-jwt-secret"


def test_settings_jwt_secret_mirrors_legacy_secret_key(monkeypatch):
    """If only SECRET_KEY is set (legacy), JWT_SECRET should mirror it."""
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.setenv("SECRET_KEY", "legacy-secret-only")
    # Drop any cached modules so `Settings()` re-reads env.
    for mod_name in [m for m in sys.modules if m.startswith("config")]:
        sys.modules.pop(mod_name, None)
    from config.settings import settings as fresh_settings

    assert fresh_settings.SECRET_KEY == "legacy-secret-only"
    assert fresh_settings.JWT_SECRET == "legacy-secret-only"


def test_settings_no_random_secret_default(monkeypatch):
    """
    Agent 6 fix: settings must NOT silently fall back to a random secret.
    With both JWT_SECRET and SECRET_KEY missing, the model loads (so import
    doesn't crash) but both attrs are None — startup will raise downstream.
    """
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    for mod_name in [m for m in sys.modules if m.startswith("config")]:
        sys.modules.pop(mod_name, None)
    from config.settings import settings as fresh_settings

    assert fresh_settings.JWT_SECRET is None
    assert fresh_settings.SECRET_KEY is None


def test_otp_service_reads_url_from_env():
    """`otp_service` uses the TWO_FACTOR_API_URL set in env."""
    from services import otp_service

    assert otp_service.TWO_FACTOR_API_URL == "https://example.invalid/v1"
    assert otp_service.TWO_FACTOR_API_KEY == "stub-key"


def test_app_is_fastapi_instance():
    """The auth service exposes a FastAPI `app` symbol — sanity-check it."""
    from fastapi import FastAPI

    # main.py imports redis at top; we patch out its startup hooks.
    import main as auth_main  # noqa: WPS433 — intentional dynamic import

    assert isinstance(auth_main.app, FastAPI)
    # Title comes from settings.PROJECT_NAME
    assert auth_main.app.title  # non-empty


def test_lifespan_raises_without_jwt_secret(monkeypatch):
    """
    Lifespan must explicitly fail when JWT_SECRET / SECRET_KEY are missing —
    no silent random fallback (Agent 6 security fix).

    The lifespan callable in `main.py` is a generator (uses `yield`); calling
    `next()` runs the validation block before the `yield`, which is where the
    missing-env check raises.
    """
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    for mod_name in [m for m in sys.modules if m.startswith(("config", "main"))]:
        sys.modules.pop(mod_name, None)

    import main as auth_main  # noqa: WPS433

    gen = auth_main.lifespan(auth_main.app)
    with pytest.raises(ValueError) as exc_info:
        # Iterating the generator runs the validation block before `yield`.
        next(gen)
    msg = str(exc_info.value)
    assert "JWT_SECRET" in msg or "SECRET_KEY" in msg
