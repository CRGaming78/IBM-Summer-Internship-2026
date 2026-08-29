"""
ESP32-C5 Simulator – sends fake WiFi frame data to the FastAPI backend.

Modes:
  1. normal       – regular beacon / probe traffic from known devices
  2. deauth_attack – flood of deauth frames from an attacker MAC
  3. rogue_ap     – beacon frames with a known SSID but different BSSID
  4. beacon_flood – many unique SSIDs appearing rapidly
  5. mixed        – random mix of normal + occasional attacks

Usage:
  python fake_esp32.py
"""

from __future__ import annotations

import random
import sys
import time
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    print("Install httpx first:  pip install httpx")
    sys.exit(1)

SERVER_URL = "http://localhost:8000/api/ingest"

# ── Realistic data pools ────────────────────────────────────────────────────

KNOWN_DEVICES = [
    "AA:BB:CC:11:22:33",
    "AA:BB:CC:44:55:66",
    "AA:BB:CC:77:88:99",
    "11:22:33:44:55:66",
    "DE:AD:BE:EF:00:01",
]

KNOWN_APS = [
    {"ssid": "HomeNetwork", "bssid": "00:11:22:33:44:55", "channel": 6},
    {"ssid": "OfficeWiFi",  "bssid": "00:11:22:33:44:AA", "channel": 1},
    {"ssid": "CafeGuest",   "bssid": "00:11:22:33:44:BB", "channel": 11},
]

RANDOM_SSIDS = [
    "FreeWiFi", "Airport_WiFi", "Hotel_Guest", "xfinitywifi",
    "ATT-WIFI", "NETGEAR_5G", "linksys", "Starbucks_WiFi",
    "eduroam", "AndroidAP", "Galaxy_S24", "iPhone_Hotspot",
    "FBI_Van", "Pretty_Fly_for_a_WiFi", "TellMyWiFiLoveHer",
]

BANDS = ["2.4GHz", "5GHz"]
CHANNELS_24 = [1, 6, 11]
CHANNELS_5 = [36, 40, 44, 48, 149, 153, 157, 161]

ATTACKER_MAC = "66:66:66:66:66:66"
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rand_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))


def _rand_channel() -> tuple[str, int]:
    band = random.choice(BANDS)
    ch = random.choice(CHANNELS_24 if band == "2.4GHz" else CHANNELS_5)
    return band, ch


# ── Frame generators ────────────────────────────────────────────────────────


def normal_frame() -> dict:
    """Generate a normal beacon or probe frame."""
    kind = random.choices(
        ["beacon", "probe_req", "probe_resp", "auth", "assoc"],
        weights=[40, 25, 15, 10, 10],
    )[0]

    if kind == "beacon":
        ap = random.choice(KNOWN_APS)
        return {
            "sensor_id": "esp32-sim",
            "band": "2.4GHz",
            "channel": ap["channel"],
            "frame_type": "beacon",
            "src_mac": ap["bssid"],
            "dst_mac": BROADCAST_MAC,
            "ssid": ap["ssid"],
            "bssid": ap["bssid"],
            "rssi": random.randint(-70, -30),
            "timestamp": _ts(),
        }

    device = random.choice(KNOWN_DEVICES)
    band, ch = _rand_channel()
    return {
        "sensor_id": "esp32-sim",
        "band": band,
        "channel": ch,
        "frame_type": kind,
        "src_mac": device,
        "dst_mac": random.choice(KNOWN_APS)["bssid"],
        "ssid": random.choice(KNOWN_APS)["ssid"] if kind == "probe_req" else None,
        "bssid": random.choice(KNOWN_APS)["bssid"],
        "rssi": random.randint(-80, -30),
        "timestamp": _ts(),
    }


def deauth_frame() -> dict:
    """Deauth flood frame from attacker."""
    ap = random.choice(KNOWN_APS)
    return {
        "sensor_id": "esp32-sim",
        "band": "2.4GHz",
        "channel": ap["channel"],
        "frame_type": "deauth",
        "src_mac": ATTACKER_MAC,
        "dst_mac": BROADCAST_MAC,
        "ssid": None,
        "bssid": ap["bssid"],
        "rssi": random.randint(-50, -20),
        "timestamp": _ts(),
    }


def rogue_ap_frame() -> dict:
    """Beacon with a known SSID but a DIFFERENT (rogue) BSSID."""
    ap = random.choice(KNOWN_APS)
    return {
        "sensor_id": "esp32-sim",
        "band": "2.4GHz",
        "channel": ap["channel"],
        "frame_type": "beacon",
        "src_mac": _rand_mac(),
        "dst_mac": BROADCAST_MAC,
        "ssid": ap["ssid"],
        "bssid": _rand_mac(),  # rogue BSSID
        "rssi": random.randint(-60, -25),
        "timestamp": _ts(),
    }


def beacon_flood_frame() -> dict:
    """Beacon with random unique SSID + BSSID to flood the airwaves."""
    bssid = _rand_mac()
    return {
        "sensor_id": "esp32-sim",
        "band": random.choice(BANDS),
        "channel": random.choice(CHANNELS_24 + CHANNELS_5),
        "frame_type": "beacon",
        "src_mac": bssid,
        "dst_mac": BROADCAST_MAC,
        "ssid": random.choice(RANDOM_SSIDS) + f"_{random.randint(1,999)}",
        "bssid": bssid,
        "rssi": random.randint(-90, -40),
        "timestamp": _ts(),
    }


# ── Simulation modes ────────────────────────────────────────────────────────


def run_normal(client: httpx.Client, fps: float) -> None:
    print("[NORMAL] Sending regular traffic… (Ctrl+C to stop)")
    while True:
        frame = normal_frame()
        _send(client, frame)
        time.sleep(1.0 / fps)


def run_deauth(client: httpx.Client, fps: float) -> None:
    print("[DEAUTH ATTACK] Flooding deauth frames… (Ctrl+C to stop)")
    while True:
        frame = deauth_frame()
        _send(client, frame)
        time.sleep(1.0 / fps)


def run_rogue(client: httpx.Client, fps: float) -> None:
    print("[ROGUE AP] Sending rogue AP beacons… (Ctrl+C to stop)")
    while True:
        frame = rogue_ap_frame()
        _send(client, frame)
        time.sleep(1.0 / fps)


def run_beacon_flood(client: httpx.Client, fps: float) -> None:
    print("[BEACON FLOOD] Flooding random SSIDs… (Ctrl+C to stop)")
    while True:
        frame = beacon_flood_frame()
        _send(client, frame)
        time.sleep(1.0 / fps)


def run_mixed(client: httpx.Client, fps: float) -> None:
    print("[MIXED] Sending mixed traffic with occasional attacks… (Ctrl+C to stop)")
    while True:
        roll = random.random()
        if roll < 0.60:
            frame = normal_frame()
        elif roll < 0.75:
            frame = deauth_frame()
        elif roll < 0.88:
            frame = rogue_ap_frame()
        else:
            frame = beacon_flood_frame()
        _send(client, frame)
        time.sleep(1.0 / fps)


def _send(client: httpx.Client, frame: dict) -> None:
    try:
        r = client.post(SERVER_URL, json=frame)
        status = r.json()
        alerts = status.get("alerts", 0)
        tag = f"  ⚠ {alerts} alert(s)!" if alerts else ""
        print(f"  → {frame['frame_type']:12s} src={frame['src_mac']}  ch={frame['channel']:>3d}  rssi={frame['rssi']:>4d}{tag}")
    except httpx.ConnectError:
        print("  ✗ Cannot reach server at", SERVER_URL)
    except Exception as e:
        print(f"  ✗ Error: {e}")


# ── Interactive menu ─────────────────────────────────────────────────────────


MODES = {
    "1": ("Normal traffic", run_normal),
    "2": ("Deauth attack", run_deauth),
    "3": ("Rogue AP", run_rogue),
    "4": ("Beacon flood", run_beacon_flood),
    "5": ("Mixed (normal + attacks)", run_mixed),
}


def main() -> None:
    print("=" * 60)
    print("  ESP32-C5 WiFi Frame Simulator")
    print("=" * 60)
    print()
    for key, (label, _) in MODES.items():
        print(f"  [{key}] {label}")
    print(f"  [q] Quit")
    print()

    choice = input("Select mode: ").strip()
    if choice == "q":
        return
    if choice not in MODES:
        print("Invalid choice.")
        return

    fps_input = input("Frames per second (default 5): ").strip()
    fps = float(fps_input) if fps_input else 5.0

    label, runner = MODES[choice]
    print(f"\nStarting '{label}' at {fps} fps → {SERVER_URL}\n")

    with httpx.Client(timeout=5.0) as client:
        try:
            runner(client, fps)
        except KeyboardInterrupt:
            print("\n\nStopped.")


if __name__ == "__main__":
    main()
