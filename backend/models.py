"""
Pydantic v2 models for request/response validation.
"""

from pydantic import BaseModel


# ── Ingest ───────────────────────────────────────────────────────────────────


class FrameData(BaseModel):
    sensor_id: str
    band: str               # "2.4GHz", "5GHz", "6GHz"
    channel: int
    frame_type: str          # beacon, probe_req, probe_resp, deauth, disassoc, auth, assoc
    src_mac: str
    dst_mac: str
    ssid: str | None = None
    bssid: str | None = None
    rssi: int
    timestamp: str           # ISO 8601


# ── Alerts ───────────────────────────────────────────────────────────────────


class AlertResponse(BaseModel):
    id: int
    alert_type: str
    severity: str
    threat_score: int
    description: str
    source_mac: str
    channel: int
    created_at: str
    acknowledged: bool

    model_config = {"from_attributes": True}


# ── Trusted devices / APs ───────────────────────────────────────────────────


class DeviceCreate(BaseModel):
    mac_address: str
    device_name: str


class DeviceResponse(BaseModel):
    id: int
    mac_address: str
    device_name: str
    added_at: str

    model_config = {"from_attributes": True}


class APCreate(BaseModel):
    ssid: str
    bssid: str
    expected_channel: int


class APResponse(BaseModel):
    id: int
    ssid: str
    bssid: str
    expected_channel: int
    added_at: str

    model_config = {"from_attributes": True}


# ── Dashboard stats ─────────────────────────────────────────────────────────


class StatsResponse(BaseModel):
    total_events: int
    active_alerts: int
    unique_devices: int
    rogue_aps: int
    threat_level: str        # CRITICAL, HIGH, WARNING, LOW
    threat_score: int = 0    # 0-100 overall threat score
