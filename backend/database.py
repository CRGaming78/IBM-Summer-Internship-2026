"""
Database setup using SQLAlchemy 2.0 async with aiosqlite.
Defines all tables: wifi_events, alerts, trusted_devices, trusted_aps.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Float, Integer, String, DateTime, func
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DATABASE_URL = "sqlite+aiosqlite:///./wifi_monitor.db"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


# ── Tables ───────────────────────────────────────────────────────────────────


class WiFiEvent(Base):
    __tablename__ = "wifi_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sensor_id: Mapped[str] = mapped_column(String, nullable=False)
    band: Mapped[str] = mapped_column(String, nullable=False)           # "2.4GHz" / "5GHz" / "6GHz"
    channel: Mapped[int] = mapped_column(Integer, nullable=False)
    frame_type: Mapped[str] = mapped_column(String, nullable=False)     # beacon, probe_req, probe_resp, deauth, disassoc, auth, assoc
    src_mac: Mapped[str] = mapped_column(String, nullable=False)
    dst_mac: Mapped[str] = mapped_column(String, nullable=False)
    ssid: Mapped[str | None] = mapped_column(String, nullable=True)
    bssid: Mapped[str | None] = mapped_column(String, nullable=True)
    rssi: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[str] = mapped_column(String, nullable=False)      # ISO format


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_type: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)       # CRITICAL, HIGH, WARNING, INFO
    threat_score: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    source_mac: Mapped[str] = mapped_column(String, nullable=False)
    channel: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[str] = mapped_column(
        String, nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)


class TrustedDevice(Base):
    __tablename__ = "trusted_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mac_address: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    device_name: Mapped[str] = mapped_column(String, nullable=False)
    added_at: Mapped[str] = mapped_column(
        String, nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )


class TrustedAP(Base):
    __tablename__ = "trusted_aps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ssid: Mapped[str] = mapped_column(String, nullable=False)
    bssid: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    expected_channel: Mapped[int] = mapped_column(Integer, nullable=False)
    added_at: Mapped[str] = mapped_column(
        String, nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )


# ── Dependency ───────────────────────────────────────────────────────────────


async def create_tables():
    """Create all tables (called once on startup)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:  # type: ignore[misc]
    """FastAPI dependency that yields an async session."""
    async with async_session() as session:
        yield session
