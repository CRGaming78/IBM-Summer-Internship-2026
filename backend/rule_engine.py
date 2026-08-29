"""
Rule-based wireless threat detection engine.

Eight detection rules with sliding-window counters and threat scoring.
Uses the strategy pattern: each rule is a subclass of DetectionRule.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models import FrameData


# ── Alert dataclass (lightweight, not the DB model) ─────────────────────────


@dataclass
class AlertInfo:
    alert_type: str
    severity: str        # CRITICAL, HIGH, WARNING, INFO
    threat_score: int
    description: str
    source_mac: str
    channel: int


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "WARNING"
    return "INFO"


# ── Base rule ────────────────────────────────────────────────────────────────


class DetectionRule(ABC):
    """Base class for all detection rules (strategy pattern)."""

    @abstractmethod
    def evaluate(self, frame: "FrameData") -> AlertInfo | None:
        """Return an AlertInfo if the rule triggers, else None."""


# ── 1. Deauth Flood  (>20 deauths in 10 s from same source → +50) ───────────


class DeauthFloodRule(DetectionRule):
    def __init__(self, threshold: int = 20, window_sec: float = 10.0):
        self.threshold = threshold
        self.window = window_sec
        # src_mac → deque of timestamps
        self._hits: dict[str, deque[float]] = defaultdict(lambda: deque())

    def evaluate(self, frame: "FrameData") -> AlertInfo | None:
        if frame.frame_type != "deauth":
            return None
        now = time.time()
        q = self._hits[frame.src_mac]
        q.append(now)
        # trim old entries
        while q and q[0] < now - self.window:
            q.popleft()
        if len(q) > self.threshold:
            score = 50
            return AlertInfo(
                alert_type="DEAUTH_FLOOD",
                severity=_severity_from_score(score),
                threat_score=score,
                description=(
                    f"Deauth flood detected: {len(q)} deauth frames from "
                    f"{frame.src_mac} in {self.window}s"
                ),
                source_mac=frame.src_mac,
                channel=frame.channel,
            )
        return None


# ── 2. Disassoc Flood  (>15 in 10 s → +40) ──────────────────────────────────


class DisassocFloodRule(DetectionRule):
    def __init__(self, threshold: int = 15, window_sec: float = 10.0):
        self.threshold = threshold
        self.window = window_sec
        self._hits: dict[str, deque[float]] = defaultdict(lambda: deque())

    def evaluate(self, frame: "FrameData") -> AlertInfo | None:
        if frame.frame_type != "disassoc":
            return None
        now = time.time()
        q = self._hits[frame.src_mac]
        q.append(now)
        while q and q[0] < now - self.window:
            q.popleft()
        if len(q) > self.threshold:
            score = 40
            return AlertInfo(
                alert_type="DISASSOC_FLOOD",
                severity=_severity_from_score(score),
                threat_score=score,
                description=(
                    f"Disassociation flood: {len(q)} frames from "
                    f"{frame.src_mac} in {self.window}s"
                ),
                source_mac=frame.src_mac,
                channel=frame.channel,
            )
        return None


# ── 3. Rogue AP  (known SSID, unknown BSSID → +80) ─────────────────────────


class RogueAPRule(DetectionRule):
    """Fires when a beacon carries a trusted SSID but from an unknown BSSID."""

    def __init__(self) -> None:
        # ssid → set of trusted BSSIDs
        self._trusted: dict[str, set[str]] = defaultdict(set)

    def load_trusted_aps(self, aps: list[tuple[str, str]]) -> None:
        """aps is a list of (ssid, bssid) pairs."""
        self._trusted.clear()
        for ssid, bssid in aps:
            self._trusted[ssid.lower()].add(bssid.lower())

    def add_trusted_ap(self, ssid: str, bssid: str) -> None:
        self._trusted[ssid.lower()].add(bssid.lower())

    def remove_trusted_ap(self, bssid: str) -> None:
        bssid_l = bssid.lower()
        for bssids in self._trusted.values():
            bssids.discard(bssid_l)

    def evaluate(self, frame: "FrameData") -> AlertInfo | None:
        if frame.frame_type != "beacon" or not frame.ssid or not frame.bssid:
            return None
        ssid_l = frame.ssid.lower()
        if ssid_l not in self._trusted:
            return None  # SSID not in our trusted list → ignore
        if frame.bssid.lower() not in self._trusted[ssid_l]:
            score = 80
            return AlertInfo(
                alert_type="ROGUE_AP",
                severity=_severity_from_score(score),
                threat_score=score,
                description=(
                    f"Rogue AP detected: SSID '{frame.ssid}' seen from "
                    f"unknown BSSID {frame.bssid}"
                ),
                source_mac=frame.bssid,
                channel=frame.channel,
            )
        return None


# ── 4. Evil Twin / Channel Anomaly  (known SSID on wrong channel → +80) ─────


class EvilTwinChannelRule(DetectionRule):
    """Fires when a trusted SSID+BSSID appears on an unexpected channel."""

    def __init__(self) -> None:
        # bssid → expected channel
        self._expected_channel: dict[str, int] = {}

    def load_trusted_aps(self, aps: list[tuple[str, str, int]]) -> None:
        """aps is (ssid, bssid, expected_channel)."""
        self._expected_channel.clear()
        for _, bssid, ch in aps:
            self._expected_channel[bssid.lower()] = ch

    def add_trusted_ap(self, bssid: str, channel: int) -> None:
        self._expected_channel[bssid.lower()] = channel

    def remove_trusted_ap(self, bssid: str) -> None:
        self._expected_channel.pop(bssid.lower(), None)

    def evaluate(self, frame: "FrameData") -> AlertInfo | None:
        if frame.frame_type != "beacon" or not frame.bssid:
            return None
        bssid_l = frame.bssid.lower()
        if bssid_l not in self._expected_channel:
            return None
        expected = self._expected_channel[bssid_l]
        if frame.channel != expected:
            score = 80
            return AlertInfo(
                alert_type="EVIL_TWIN_CHANNEL",
                severity=_severity_from_score(score),
                threat_score=score,
                description=(
                    f"Evil twin / channel anomaly: BSSID {frame.bssid} expected "
                    f"on ch {expected} but seen on ch {frame.channel}"
                ),
                source_mac=frame.bssid,
                channel=frame.channel,
            )
        return None


# ── 5. Beacon Flood  (>50 unique BSSIDs in 30 s → +60) ──────────────────────


class BeaconFloodRule(DetectionRule):
    def __init__(self, threshold: int = 50, window_sec: float = 30.0):
        self.threshold = threshold
        self.window = window_sec
        # deque of (timestamp, bssid)
        self._recent: deque[tuple[float, str]] = deque()

    def evaluate(self, frame: "FrameData") -> AlertInfo | None:
        if frame.frame_type != "beacon" or not frame.bssid:
            return None
        now = time.time()
        self._recent.append((now, frame.bssid.lower()))
        while self._recent and self._recent[0][0] < now - self.window:
            self._recent.popleft()
        unique = {b for _, b in self._recent}
        if len(unique) > self.threshold:
            score = 60
            return AlertInfo(
                alert_type="BEACON_FLOOD",
                severity=_severity_from_score(score),
                threat_score=score,
                description=(
                    f"Beacon flood: {len(unique)} unique BSSIDs in {self.window}s"
                ),
                source_mac=frame.bssid,
                channel=frame.channel,
            )
        return None


# ── 6. Unknown Device  (MAC not in whitelist → +20) ─────────────────────────


class UnknownDeviceRule(DetectionRule):
    def __init__(self) -> None:
        self._whitelist: set[str] = set()
        self._already_alerted: set[str] = set()  # avoid repeat alerts

    def load_whitelist(self, macs: list[str]) -> None:
        self._whitelist = {m.lower() for m in macs}
        self._already_alerted.clear()

    def add_to_whitelist(self, mac: str) -> None:
        self._whitelist.add(mac.lower())

    def remove_from_whitelist(self, mac: str) -> None:
        self._whitelist.discard(mac.lower())
        self._already_alerted.discard(mac.lower())

    def evaluate(self, frame: "FrameData") -> AlertInfo | None:
        mac = frame.src_mac.lower()
        if mac in self._whitelist or mac in self._already_alerted:
            return None
        # Don't alert on broadcast
        if mac == "ff:ff:ff:ff:ff:ff":
            return None
        self._already_alerted.add(mac)
        score = 20
        return AlertInfo(
            alert_type="UNKNOWN_DEVICE",
            severity=_severity_from_score(score),
            threat_score=score,
            description=f"Unknown device detected: {frame.src_mac}",
            source_mac=frame.src_mac,
            channel=frame.channel,
        )


# ── 7. Probe Harvest  (>10 unique SSIDs probed by same MAC in 60 s → +30) ──


class ProbeHarvestRule(DetectionRule):
    def __init__(self, threshold: int = 10, window_sec: float = 60.0):
        self.threshold = threshold
        self.window = window_sec
        # src_mac → deque of (timestamp, ssid)
        self._probes: dict[str, deque[tuple[float, str]]] = defaultdict(lambda: deque())

    def evaluate(self, frame: "FrameData") -> AlertInfo | None:
        if frame.frame_type != "probe_req" or not frame.ssid:
            return None
        now = time.time()
        q = self._probes[frame.src_mac]
        q.append((now, frame.ssid.lower()))
        while q and q[0][0] < now - self.window:
            q.popleft()
        unique_ssids = {s for _, s in q}
        if len(unique_ssids) > self.threshold:
            score = 30
            return AlertInfo(
                alert_type="PROBE_HARVEST",
                severity=_severity_from_score(score),
                threat_score=score,
                description=(
                    f"Probe harvesting: {frame.src_mac} probed "
                    f"{len(unique_ssids)} unique SSIDs in {self.window}s"
                ),
                source_mac=frame.src_mac,
                channel=frame.channel,
            )
        return None


# ── 8. RSSI Anomaly  (known AP RSSI deviation > 15 dBm → +25) ──────────────


class RSSIAnomalyRule(DetectionRule):
    def __init__(self, deviation_threshold: int = 15, history_size: int = 50):
        self.deviation_threshold = deviation_threshold
        self.history_size = history_size
        # bssid → deque of recent RSSI values
        self._history: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=history_size))
        # bssid set of known/trusted APs
        self._trusted_bssids: set[str] = set()

    def load_trusted_aps(self, bssids: list[str]) -> None:
        self._trusted_bssids = {b.lower() for b in bssids}

    def add_trusted_ap(self, bssid: str) -> None:
        self._trusted_bssids.add(bssid.lower())

    def remove_trusted_ap(self, bssid: str) -> None:
        self._trusted_bssids.discard(bssid.lower())

    def evaluate(self, frame: "FrameData") -> AlertInfo | None:
        if frame.frame_type != "beacon" or not frame.bssid:
            return None
        bssid_l = frame.bssid.lower()
        if bssid_l not in self._trusted_bssids:
            return None
        history = self._history[bssid_l]
        if len(history) >= 5:  # need some baseline
            avg_rssi = sum(history) / len(history)
            deviation = abs(frame.rssi - avg_rssi)
            if deviation > self.deviation_threshold:
                score = 25
                history.append(frame.rssi)
                return AlertInfo(
                    alert_type="RSSI_ANOMALY",
                    severity=_severity_from_score(score),
                    threat_score=score,
                    description=(
                        f"RSSI anomaly on {frame.bssid}: expected ~{avg_rssi:.0f} dBm, "
                        f"got {frame.rssi} dBm (Δ{deviation:.0f})"
                    ),
                    source_mac=frame.bssid,
                    channel=frame.channel,
                )
        history.append(frame.rssi)
        return None


# ── Detection Engine (orchestrator) ─────────────────────────────────────────


class DetectionEngine:
    """Runs every incoming frame through all rules and collects alerts."""

    def __init__(self) -> None:
        self.deauth_flood = DeauthFloodRule()
        self.disassoc_flood = DisassocFloodRule()
        self.rogue_ap = RogueAPRule()
        self.evil_twin = EvilTwinChannelRule()
        self.beacon_flood = BeaconFloodRule()
        self.unknown_device = UnknownDeviceRule()
        self.probe_harvest = ProbeHarvestRule()
        self.rssi_anomaly = RSSIAnomalyRule()

        self._rules: list[DetectionRule] = [
            self.deauth_flood,
            self.disassoc_flood,
            self.rogue_ap,
            self.evil_twin,
            self.beacon_flood,
            self.unknown_device,
            self.probe_harvest,
            self.rssi_anomaly,
        ]

    # ── bulk-load from DB on startup ─────────────────────────────────────

    def load_whitelist(self, macs: list[str]) -> None:
        self.unknown_device.load_whitelist(macs)

    def load_trusted_aps(self, aps: list[tuple[str, str, int]]) -> None:
        """aps: list of (ssid, bssid, expected_channel)."""
        self.rogue_ap.load_trusted_aps([(s, b) for s, b, _ in aps])
        self.evil_twin.load_trusted_aps(aps)
        self.rssi_anomaly.load_trusted_aps([b for _, b, _ in aps])

    # ── dynamic updates ──────────────────────────────────────────────────

    def add_whitelist(self, mac: str) -> None:
        self.unknown_device.add_to_whitelist(mac)

    def remove_whitelist(self, mac: str) -> None:
        self.unknown_device.remove_from_whitelist(mac)

    def add_trusted_ap(self, ssid: str, bssid: str, channel: int) -> None:
        self.rogue_ap.add_trusted_ap(ssid, bssid)
        self.evil_twin.add_trusted_ap(bssid, channel)
        self.rssi_anomaly.add_trusted_ap(bssid)

    def remove_trusted_ap(self, bssid: str) -> None:
        self.rogue_ap.remove_trusted_ap(bssid)
        self.evil_twin.remove_trusted_ap(bssid)
        self.rssi_anomaly.remove_trusted_ap(bssid)

    # ── evaluation ───────────────────────────────────────────────────────

    def evaluate(self, frame: "FrameData") -> list[AlertInfo]:
        """Run frame through every rule, return list of triggered alerts."""
        alerts: list[AlertInfo] = []
        for rule in self._rules:
            result = rule.evaluate(frame)
            if result is not None:
                alerts.append(result)
        return alerts
