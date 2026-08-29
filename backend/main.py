"""
FastAPI application – Wireless Network Security Monitoring System.

Wires together: database, models, rule_engine, WebSocket broadcast.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import Alert, TrustedAP, TrustedDevice, WiFiEvent, async_session, create_tables, get_db
from models import (
    AlertResponse,
    APCreate,
    APResponse,
    DeviceCreate,
    DeviceResponse,
    FrameData,
    StatsResponse,
)
from rule_engine import DetectionEngine
from behavior_profiler import BehaviorProfiler


# ── WebSocket manager ────────────────────────────────────────────────────────


class ConnectionManager:
    """Keeps track of active WebSocket connections and broadcasts messages."""

    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.active.remove(ws)

    async def broadcast(self, data: dict) -> None:
        payload = json.dumps(data, default=str)
        for ws in list(self.active):
            try:
                await ws.send_text(payload)
            except Exception:
                self.active.remove(ws)


manager = ConnectionManager()
engine_det = DetectionEngine()
profiler = BehaviorProfiler()


# ── Lifespan ─────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables, load whitelist + trusted APs into engine
    await create_tables()

    async with async_session() as session:
        # Load whitelist
        result = await session.execute(select(TrustedDevice.mac_address))
        macs = [row[0] for row in result.all()]
        engine_det.load_whitelist(macs)

        # Load trusted APs
        result = await session.execute(
            select(TrustedAP.ssid, TrustedAP.bssid, TrustedAP.expected_channel)
        )
        aps = [(r[0], r[1], r[2]) for r in result.all()]
        engine_det.load_trusted_aps(aps)

    # Start behavior profiler background task
    global _profiler_task, _cleanup_task
    _profiler_task = asyncio.create_task(_profiler_loop())
    _cleanup_task = asyncio.create_task(_db_cleanup_loop())
    print("[Profiler] Background task started")
    print("[Cleanup] DB cleanup task started (72h retention)")

    yield  # app is running
    # Shutdown: cancel background tasks
    for task in [_profiler_task, _cleanup_task]:
        if task and not task.done():
            task.cancel()


# ── App ──────────────────────────────────────────────────────────────────────


app = FastAPI(
    title="WiFi Security Monitor",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (dashboard) — directory created separately
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Profiler background task ─────────────────────────────────────────────────

import asyncio

_profiler_task: asyncio.Task | None = None

async def _profiler_loop():
    """Background loop: rebuild baselines every 60s, evaluate every 30s."""
    REBUILD_INTERVAL = 60    # rebuild baselines every 60 seconds
    EVAL_INTERVAL = 30       # evaluate behavior every 30 seconds

    # Wait a few seconds for initial data to accumulate
    await asyncio.sleep(5)

    # Initial baseline build
    try:
        await profiler.rebuild_baselines()
    except Exception as e:
        print(f"[Profiler] Initial baseline build failed: {e}")

    last_rebuild = asyncio.get_event_loop().time()

    while True:
        try:
            # Rebuild baselines periodically (or immediately if none are mature)
            now = asyncio.get_event_loop().time()
            has_mature = any(b.is_mature() for b in profiler.baselines.values())
            if now - last_rebuild >= REBUILD_INTERVAL or not has_mature:
                await profiler.rebuild_baselines()
                last_rebuild = now

            # Evaluate current behavior
            risks = await profiler.evaluate_all()

            # Broadcast behavior update to dashboard
            if risks:
                risk_data = {mac: r.to_dict() for mac, r in risks.items()}
                await manager.broadcast({
                    "type": "behavior_update",
                    "risks": risk_data,
                })

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[Profiler] Error in evaluation loop: {e}")

        await asyncio.sleep(EVAL_INTERVAL)


_cleanup_task: asyncio.Task | None = None

async def _db_cleanup_loop():
    """Background loop: delete old events and acknowledged alerts every hour."""
    CLEANUP_INTERVAL = 3600  # 1 hour
    RETENTION_HOURS = 72     # keep 72 hours of data

    await asyncio.sleep(30)  # wait for startup to finish

    while True:
        try:
            async with async_session() as db:
                cutoff = (datetime.now(timezone.utc) - timedelta(hours=RETENTION_HOURS)).isoformat()

                # Delete old events
                result = await db.execute(
                    delete(WiFiEvent).where(WiFiEvent.timestamp < cutoff)
                )
                events_deleted = result.rowcount

                # Delete old acknowledged alerts
                result2 = await db.execute(
                    delete(Alert).where(Alert.acknowledged == True, Alert.timestamp < cutoff)  # noqa: E712
                )
                alerts_deleted = result2.rowcount

                await db.commit()

                if events_deleted or alerts_deleted:
                    print(f"[Cleanup] Deleted {events_deleted} old events, {alerts_deleted} old alerts (>{RETENTION_HOURS}h)")

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[Cleanup] Error: {e}")

        await asyncio.sleep(CLEANUP_INTERVAL)


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════


# ── POST /api/ingest ─────────────────────────────────────────────────────────


@app.post("/api/ingest")
async def ingest_frame(frame: FrameData, db: AsyncSession = Depends(get_db)):
    """Receive a WiFi frame, store it, run detection, broadcast via WS."""

    # 1. Store event
    event = WiFiEvent(
        sensor_id=frame.sensor_id,
        band=frame.band,
        channel=frame.channel,
        frame_type=frame.frame_type,
        src_mac=frame.src_mac,
        dst_mac=frame.dst_mac,
        ssid=frame.ssid,
        bssid=frame.bssid,
        rssi=frame.rssi,
        timestamp=frame.timestamp,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)

    # 2. Run detection engine
    alerts_info = engine_det.evaluate(frame)

    # 3. Persist any alerts
    alert_rows: list[dict] = []
    for a in alerts_info:
        row = Alert(
            alert_type=a.alert_type,
            severity=a.severity,
            threat_score=a.threat_score,
            description=a.description,
            source_mac=a.source_mac,
            channel=a.channel,
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)
        alert_rows.append(AlertResponse.model_validate(row).model_dump())

    # 4. Broadcast to WebSocket clients
    event_data = {
        "id": event.id,
        "sensor_id": event.sensor_id,
        "band": event.band,
        "channel": event.channel,
        "frame_type": event.frame_type,
        "src_mac": event.src_mac,
        "dst_mac": event.dst_mac,
        "ssid": event.ssid,
        "bssid": event.bssid,
        "rssi": event.rssi,
        "timestamp": event.timestamp,
    }
    await manager.broadcast({"type": "new_event", "event": event_data, "alerts": alert_rows})

    return {"status": "ok", "event_id": event.id, "alerts": len(alert_rows)}


# ── GET /api/alerts ──────────────────────────────────────────────────────────


@app.get("/api/alerts", response_model=list[AlertResponse])
async def list_alerts(
    severity: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Alert).order_by(Alert.id.desc()).limit(limit)
    if severity:
        stmt = stmt.where(Alert.severity == severity.upper())
    result = await db.execute(stmt)
    return result.scalars().all()


# ── PUT /api/alerts/{id}/acknowledge ─────────────────────────────────────────


@app.put("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        return {"error": "Alert not found"}
    alert.acknowledged = True
    await db.commit()
    return {"status": "acknowledged"}


# ── GET /api/stats ───────────────────────────────────────────────────────────


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats(db: AsyncSession = Depends(get_db)):
    total_events = (await db.execute(select(func.count(WiFiEvent.id)))).scalar() or 0
    active_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.acknowledged == False)  # noqa: E712
        )
    ).scalar() or 0
    unique_devices = (
        await db.execute(select(func.count(func.distinct(WiFiEvent.src_mac))))
    ).scalar() or 0
    rogue_aps = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.alert_type == "ROGUE_AP", Alert.acknowledged == False)  # noqa: E712
        )
    ).scalar() or 0

    # Determine overall threat level from most recent unacknowledged alerts
    latest = (
        await db.execute(
            select(Alert.severity)
            .where(Alert.acknowledged == False)  # noqa: E712
            .order_by(Alert.id.desc())
            .limit(10)
        )
    ).scalars().all()

    if "CRITICAL" in latest:
        threat_level = "CRITICAL"
    elif "HIGH" in latest:
        threat_level = "HIGH"
    elif "WARNING" in latest:
        threat_level = "WARNING"
    else:
        threat_level = "LOW"

    return StatsResponse(
        total_events=total_events,
        active_alerts=active_alerts,
        unique_devices=unique_devices,
        rogue_aps=rogue_aps,
        threat_level=threat_level,
        threat_score=0,
    )


# ── GET /api/device-scores ──────────────────────────────────────────────────


@app.get("/api/device-scores")
async def get_device_scores():
    """Return per-MAC risk scores from the behavior profiler."""
    risks = profiler.get_all_risks()
    # Return {mac: score} for backward compatibility with the dashboard
    return {mac: r["risk_score"] for mac, r in risks.items()}


# ── GET /api/device-risks ───────────────────────────────────────────────────


@app.get("/api/device-risks")
async def get_device_risks():
    """Return full risk details (score + reasons) for all devices."""
    return profiler.get_all_risks()


# ── GET /api/device-baseline/{mac} ──────────────────────────────────────────


@app.get("/api/device-baseline/{mac}")
async def get_device_baseline(mac: str, db: AsyncSession = Depends(get_db)):
    """Return baseline vs current comparison for a device."""
    baseline = profiler.baselines.get(mac)
    risk = profiler.risks.get(mac)

    if not baseline:
        return {"error": "No baseline for this device", "mac": mac}

    # Get current window stats (last 5 min)
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

    # Current packet count
    pkt_result = await db.execute(
        select(func.count(WiFiEvent.id))
        .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
    )
    current_pkts = pkt_result.scalar() or 0

    # Current frame distribution
    ft_result = await db.execute(
        select(WiFiEvent.frame_type, func.count(WiFiEvent.id))
        .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
        .group_by(WiFiEvent.frame_type)
    )
    current_ft = {row[0]: row[1] for row in ft_result.all()}
    total_ft = sum(current_ft.values()) or 1
    current_dist = {ft: round(c / total_ft * 100, 1) for ft, c in current_ft.items()}

    # Current destination count
    dest_result = await db.execute(
        select(func.count(func.distinct(WiFiEvent.dst_mac)))
        .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
    )
    current_dests = dest_result.scalar() or 0

    # Current channel count
    chan_result = await db.execute(
        select(func.count(func.distinct(WiFiEvent.channel)))
        .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
    )
    current_chans = chan_result.scalar() or 0

    # Format baseline frame dist as percentages
    baseline_dist = {ft: round(pct * 100, 1) for ft, pct in baseline.frame_dist.items()}

    return {
        "mac": mac,
        "risk_score": risk.risk_score if risk else 0,
        "reasons": risk.reasons if risk else [],
        "total_events": baseline.total_events,
        "first_seen": baseline.first_seen,
        "last_seen": baseline.last_seen,
        "baseline": {
            "pkt_rate_avg": round(baseline.pkt_rate_avg, 1),
            "pkt_rate_std": round(baseline.pkt_rate_std, 1),
            "active_hours": sorted(list(baseline.active_hours)),
            "frame_dist": baseline_dist,
            "dest_avg": round(baseline.dest_avg, 1),
            "chan_avg": round(baseline.chan_avg, 1),
            "known_dests_count": len(baseline.known_dests),
        },
        "current": {
            "pkt_count": current_pkts,
            "frame_dist": current_dist,
            "dest_count": current_dests,
            "chan_count": current_chans,
            "hour": datetime.now(timezone.utc).hour,
        }
    }


# ── GET /api/timeline ───────────────────────────────────────────────────────


@app.get("/api/timeline")
async def get_timeline(
    minutes: int = Query(30, ge=1, le=1440),
    db: AsyncSession = Depends(get_db),
):
    """Time-series frame counts grouped by frame_type per minute."""
    stmt = text(
        """
        SELECT
            strftime('%Y-%m-%dT%H:%M:00', timestamp) AS minute,
            frame_type,
            COUNT(*) AS count
        FROM wifi_events
        WHERE timestamp >= datetime('now', :offset)
        GROUP BY minute, frame_type
        ORDER BY minute
        """
    )
    result = await db.execute(stmt, {"offset": f"-{minutes} minutes"})
    rows = result.all()

    timeline: dict[str, dict[str, int]] = {}
    for minute, frame_type, count in rows:
        timeline.setdefault(minute, {})[frame_type] = count

    return [
        {"minute": m, "counts": c} for m, c in timeline.items()
    ]


# ── GET /api/devices ─────────────────────────────────────────────────────────


@app.get("/api/devices")
async def list_devices(db: AsyncSession = Depends(get_db)):
    """Unique source MACs with their last-seen timestamp and frame count."""
    stmt = text(
        """
        SELECT src_mac, MAX(timestamp) AS last_seen, COUNT(*) AS frame_count
        FROM wifi_events
        GROUP BY src_mac
        ORDER BY last_seen DESC
        """
    )
    result = await db.execute(stmt)
    return [
        {"mac": row[0], "last_seen": row[1], "frame_count": row[2]}
        for row in result.all()
    ]


# ── GET /api/access-points ──────────────────────────────────────────────────


@app.get("/api/access-points")
async def list_access_points(db: AsyncSession = Depends(get_db)):
    """Detected access points (from beacon frames)."""
    stmt = text(
        """
        SELECT bssid, ssid, channel, MIN(rssi) AS min_rssi, MAX(rssi) AS max_rssi,
               COUNT(*) AS beacon_count, MAX(timestamp) AS last_seen
        FROM wifi_events
        WHERE frame_type = 'beacon' AND bssid IS NOT NULL
        GROUP BY bssid
        ORDER BY last_seen DESC
        """
    )
    result = await db.execute(stmt)
    return [
        {
            "bssid": r[0],
            "ssid": r[1],
            "channel": r[2],
            "min_rssi": r[3],
            "max_rssi": r[4],
            "beacon_count": r[5],
            "last_seen": r[6],
        }
        for r in result.all()
    ]


# ── Whitelist CRUD ───────────────────────────────────────────────────────────


@app.get("/api/whitelist", response_model=list[DeviceResponse])
async def list_whitelist(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(TrustedDevice).order_by(TrustedDevice.id))
    return result.scalars().all()


@app.post("/api/whitelist", response_model=DeviceResponse)
async def add_to_whitelist(device: DeviceCreate, db: AsyncSession = Depends(get_db)):
    row = TrustedDevice(mac_address=device.mac_address, device_name=device.device_name)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    engine_det.add_whitelist(device.mac_address)
    return row


@app.delete("/api/whitelist/{mac}")
async def remove_from_whitelist(mac: str, db: AsyncSession = Depends(get_db)):
    await db.execute(delete(TrustedDevice).where(TrustedDevice.mac_address == mac))
    await db.commit()
    engine_det.remove_whitelist(mac)
    return {"status": "removed"}


# ── Trusted APs CRUD ────────────────────────────────────────────────────────


@app.get("/api/trusted-aps", response_model=list[APResponse])
async def list_trusted_aps(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(TrustedAP).order_by(TrustedAP.id))
    return result.scalars().all()


@app.post("/api/trusted-aps", response_model=APResponse)
async def add_trusted_ap(ap: APCreate, db: AsyncSession = Depends(get_db)):
    row = TrustedAP(ssid=ap.ssid, bssid=ap.bssid, expected_channel=ap.expected_channel)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    engine_det.add_trusted_ap(ap.ssid, ap.bssid, ap.expected_channel)
    return row


@app.delete("/api/trusted-aps/{bssid}")
async def remove_trusted_ap(bssid: str, db: AsyncSession = Depends(get_db)):
    await db.execute(delete(TrustedAP).where(TrustedAP.bssid == bssid))
    await db.commit()
    engine_det.remove_trusted_ap(bssid)
    return {"status": "removed"}


# ── WebSocket ────────────────────────────────────────────────────────────────


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ── Simulator (runs inline, no external script needed) ──────────────────────

import asyncio
import random as _rnd

_sim_task: asyncio.Task | None = None
_SIM_APS = [
    {"ssid": "HomeNetwork", "bssid": "00:11:22:33:44:55", "channel": 6},
    {"ssid": "OfficeWiFi",  "bssid": "00:11:22:33:44:AA", "channel": 1},
    {"ssid": "CafeGuest",   "bssid": "00:11:22:33:44:BB", "channel": 11},
]
_SIM_MACS = ["AA:BB:CC:11:22:33", "AA:BB:CC:44:55:66", "DE:AD:BE:EF:00:01"]
_ATTACKER_MAC = "66:66:66:66:66:66"

def _rand_mac():
    return ":".join(f"{_rnd.randint(0,255):02X}" for _ in range(6))

def _ts():
    return datetime.now(timezone.utc).isoformat()

def _normal_frame():
    ap = _rnd.choice(_SIM_APS)
    return FrameData(sensor_id="sim", band="2.4GHz", channel=ap["channel"],
        frame_type=_rnd.choice(["beacon","probe_req","probe_resp","auth"]),
        src_mac=ap["bssid"], dst_mac="FF:FF:FF:FF:FF:FF",
        ssid=ap["ssid"], bssid=ap["bssid"],
        rssi=_rnd.randint(-70,-30), timestamp=_ts())

def _deauth_frame():
    ap = _rnd.choice(_SIM_APS)
    return FrameData(sensor_id="sim", band="2.4GHz", channel=ap["channel"],
        frame_type="deauth", src_mac=_ATTACKER_MAC, dst_mac="FF:FF:FF:FF:FF:FF",
        ssid=None, bssid=ap["bssid"],
        rssi=_rnd.randint(-50,-20), timestamp=_ts())

def _rogue_frame():
    ap = _rnd.choice(_SIM_APS)
    rogue_bssid = _rand_mac()
    return FrameData(sensor_id="sim", band="2.4GHz", channel=ap["channel"],
        frame_type="beacon", src_mac=rogue_bssid, dst_mac="FF:FF:FF:FF:FF:FF",
        ssid=ap["ssid"], bssid=rogue_bssid,
        rssi=_rnd.randint(-60,-25), timestamp=_ts())

def _beacon_flood_frame():
    bssid = _rand_mac()
    return FrameData(sensor_id="sim", band="2.4GHz",
        channel=_rnd.choice([1,6,11]),
        frame_type="beacon", src_mac=bssid, dst_mac="FF:FF:FF:FF:FF:FF",
        ssid=_rnd.choice(["FreeWiFi","FBI_Van","xfinitywifi","AndroidAP"]) + f"_{_rnd.randint(1,999)}",
        bssid=bssid, rssi=_rnd.randint(-90,-40), timestamp=_ts())

async def _run_sim(scenario: str):
    """Background task that generates fake frames and pushes them through the pipeline."""
    async with async_session() as db:
        while True:
            if scenario == "normal":
                frame = _normal_frame()
            elif scenario == "deauth":
                frame = _deauth_frame()
            elif scenario == "rogue_ap":
                frame = _rogue_frame()
            elif scenario == "beacon_flood":
                frame = _beacon_flood_frame()
            else:
                return

            # Run through the same pipeline as real frames
            event = WiFiEvent(
                sensor_id=frame.sensor_id, band=frame.band, channel=frame.channel,
                frame_type=frame.frame_type, src_mac=frame.src_mac, dst_mac=frame.dst_mac,
                ssid=frame.ssid, bssid=frame.bssid, rssi=frame.rssi, timestamp=frame.timestamp,
            )
            db.add(event)
            await db.commit()
            await db.refresh(event)

            alerts_info = engine_det.evaluate(frame)
            alert_rows = []
            for a in alerts_info:
                row = Alert(alert_type=a.alert_type, severity=a.severity,
                    threat_score=a.threat_score, description=a.description,
                    source_mac=a.source_mac, channel=a.channel)
                db.add(row)
                await db.commit()
                await db.refresh(row)
                alert_rows.append(AlertResponse.model_validate(row).model_dump())

            event_data = {
                "id": event.id, "sensor_id": event.sensor_id, "band": event.band,
                "channel": event.channel, "frame_type": event.frame_type,
                "src_mac": event.src_mac, "dst_mac": event.dst_mac,
                "ssid": event.ssid, "bssid": event.bssid,
                "rssi": event.rssi, "timestamp": event.timestamp,
            }
            await manager.broadcast({"type": "new_event", "event": event_data, "alerts": alert_rows})

            delay = 0.2 if scenario == "normal" else 0.05
            await asyncio.sleep(delay)


@app.post("/api/simulator/{scenario}")
async def simulator_control(scenario: str):
    """Start/stop simulated traffic scenarios from the dashboard."""
    global _sim_task

    valid = ["normal", "deauth", "rogue_ap", "beacon_flood", "stop"]
    if scenario not in valid:
        return {"error": f"Unknown scenario. Valid: {valid}"}

    # Stop any running simulation
    if _sim_task and not _sim_task.done():
        _sim_task.cancel()
        _sim_task = None

    if scenario == "stop":
        return {"status": "ok", "scenario": "stop", "message": "Simulation stopped."}

    # Start new simulation
    _sim_task = asyncio.create_task(_run_sim(scenario))
    return {"status": "ok", "scenario": scenario, "message": f"Simulation '{scenario}' started."}


# ── Report generation ────────────────────────────────────────────────────────


@app.get("/api/report")
async def generate_report(db: AsyncSession = Depends(get_db)):
    """Generate a downloadable HTML report of the current system state."""
    from fastapi.responses import HTMLResponse

    # Gather data
    total_events = (await db.execute(select(func.count(WiFiEvent.id)))).scalar() or 0
    active_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.acknowledged == False)
    )).scalar() or 0
    unique_devices = (await db.execute(
        select(func.count(func.distinct(WiFiEvent.src_mac)))
    )).scalar() or 0

    # Recent alerts
    alert_result = await db.execute(
        select(Alert).order_by(Alert.id.desc()).limit(50)
    )
    alerts = alert_result.scalars().all()

    # Access points
    ap_result = await db.execute(select(TrustedAP))
    trusted_aps = ap_result.scalars().all()

    # Device risks
    risks = profiler.get_all_risks()
    baselines = profiler.baselines

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build HTML
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Security Report - {now_str}</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; color: #333; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: 8px; }}
h2 {{ color: #555; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 13px; }}
th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; }}
th {{ background: #f5f5f5; font-weight: 600; }}
.score-safe {{ color: #28a745; font-weight: 700; }}
.score-warn {{ color: #ffc107; font-weight: 700; }}
.score-high {{ color: #fd7e14; font-weight: 700; }}
.score-crit {{ color: #dc3545; font-weight: 700; }}
.sev-critical {{ color: #dc3545; font-weight: 700; }}
.sev-high {{ color: #fd7e14; }}
.sev-warning {{ color: #ffc107; }}
.sev-low {{ color: #28a745; }}
.reason {{ font-size: 12px; color: #666; }}
.meta {{ color: #888; font-size: 12px; }}
</style>
</head><body>
<h1>Wireless Security Monitor — Report</h1>
<p class="meta">Generated: {now_str}</p>

<h2>System Summary</h2>
<table>
<tr><th>Total Frames Captured</th><td>{total_events:,}</td></tr>
<tr><th>Active Alerts</th><td>{active_alerts:,}</td></tr>
<tr><th>Unique Devices</th><td>{unique_devices:,}</td></tr>
<tr><th>Trusted APs</th><td>{len(trusted_aps)}</td></tr>
<tr><th>Profiled Devices</th><td>{len(baselines)}</td></tr>
</table>

<h2>Device Behavior Profiles &amp; Risk Scores</h2>
<table>
<tr><th>MAC Address</th><th>Score</th><th>Events</th><th>Active Hours</th><th>Reasons</th></tr>
"""
    # Sort by risk score descending
    sorted_risks = sorted(risks.items(), key=lambda x: x[1]["risk_score"], reverse=True)
    for mac, risk in sorted_risks:
        score = risk["risk_score"]
        sc = "score-crit" if score >= 75 else "score-high" if score >= 50 else "score-warn" if score >= 25 else "score-safe"
        bl = baselines.get(mac)
        events = bl.total_events if bl else 0
        hours = ", ".join(f"{h}:00" for h in sorted(bl.active_hours)) if bl and bl.active_hours else "N/A"
        reasons = "<br>".join(risk["reasons"]) if risk["reasons"] else "Normal"

        html += f'<tr><td><code>{mac}</code></td><td class="{sc}">{score}</td>'
        html += f'<td>{events}</td><td style="font-size:11px">{hours}</td>'
        html += f'<td class="reason">{reasons}</td></tr>\n'

    html += """</table>

<h2>Recent Alerts (Last 50)</h2>
<table>
<tr><th>ID</th><th>Type</th><th>Severity</th><th>Score</th><th>Source MAC</th><th>Channel</th><th>Description</th></tr>
"""
    for a in alerts:
        sev_cls = f"sev-{(a.severity or 'low').lower()}"
        html += f'<tr><td>{a.id}</td><td>{a.alert_type}</td>'
        html += f'<td class="{sev_cls}">{a.severity}</td>'
        html += f'<td>{a.threat_score}</td>'
        html += f'<td><code>{a.source_mac or "—"}</code></td>'
        html += f'<td>{a.channel or "—"}</td>'
        html += f'<td style="font-size:12px">{a.description or ""}</td></tr>\n'

    html += """</table>

<h2>Trusted Access Points</h2>
<table>
<tr><th>SSID</th><th>BSSID</th><th>Expected Channel</th></tr>
"""
    for ap in trusted_aps:
        html += f'<tr><td>{ap.ssid}</td><td><code>{ap.bssid}</code></td><td>{ap.expected_channel}</td></tr>\n'

    html += """</table>

<hr>
<p class="meta">Report generated by Wireless Security Monitor — Device Behavior Fingerprinting &amp; Risk Scoring System</p>
</body></html>"""

    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html"'}
    )


# ── Serve dashboard ─────────────────────────────────────────────────────────


@app.get("/")
async def serve_dashboard():
    index = os.path.join("static", "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return {"message": "Dashboard not deployed yet. Place index.html in static/"}


@app.get("/about")
async def serve_about():
    about = os.path.join("static", "about.html")
    if os.path.exists(about):
        return FileResponse(about)
    return {"message": "About page not found."}


# ── Run directly ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
