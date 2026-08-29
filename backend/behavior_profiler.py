"""
Device Behavior Fingerprinting and Risk Scoring Module.

Builds per-device behavioral baselines from historical WiFi event data,
then evaluates live behavior against those baselines to produce risk
scores with plain-English explanations.

No machine learning — uses simple statistical baselines (mean + std dev).
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import func, select, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from database import WiFiEvent, async_session


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class DeviceBaseline:
    """Historical behavioral baseline for a single device."""
    mac: str
    total_events: int = 0
    first_seen: str = ""
    last_seen: str = ""

    # Packet rate (packets per 5-min window)
    pkt_rate_avg: float = 0.0
    pkt_rate_std: float = 0.0

    # Active hours (set of hour-of-day integers 0-23)
    active_hours: set[int] = field(default_factory=set)

    # Frame type distribution (normalized 0.0-1.0)
    frame_dist: dict[str, float] = field(default_factory=dict)

    # Destination diversity (unique dst_macs per 5-min window)
    dest_avg: float = 0.0
    dest_std: float = 0.0

    # Known destinations (all dst_macs ever seen)
    known_dests: set[str] = field(default_factory=set)

    # Channel spread (unique channels per 5-min window)
    chan_avg: float = 0.0
    chan_std: float = 0.0

    def is_mature(self) -> bool:
        """Baseline needs enough data before we flag anomalies."""
        return self.total_events >= 50


@dataclass
class DeviceRisk:
    """Current risk assessment for a device."""
    mac: str
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mac": self.mac,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
        }


# ── Profiler ─────────────────────────────────────────────────────────────────


class BehaviorProfiler:
    """Builds baselines and evaluates device behavior."""

    # Weights for each anomaly dimension (max contribution to score)
    W_PACKET_RATE = 25
    W_ACTIVE_HOURS = 15
    W_FRAME_DIST = 20
    W_DEST_DIVERSITY = 15
    W_NEW_DESTS = 15
    W_CHANNEL_SPREAD = 10

    # Minimum data for baseline
    MIN_EVENTS = 50
    # How far back to look for baseline data (hours)
    BASELINE_HOURS = 24
    # Current evaluation window (minutes)
    EVAL_WINDOW_MIN = 5

    def __init__(self) -> None:
        self.baselines: dict[str, DeviceBaseline] = {}
        self.risks: dict[str, DeviceRisk] = {}
        self._last_rebuild: float = 0

    # ── Build baselines from historical data ─────────────────────────────

    async def rebuild_baselines(self) -> None:
        """Query wifi_events and build per-device baselines."""
        async with async_session() as db:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=self.BASELINE_HOURS)).isoformat()

            # Get all devices with activity in the baseline window
            result = await db.execute(
                select(WiFiEvent.src_mac, func.count(WiFiEvent.id))
                .where(WiFiEvent.timestamp >= cutoff)
                .group_by(WiFiEvent.src_mac)
            )
            device_counts = {row[0]: row[1] for row in result.all()}

            for mac, count in device_counts.items():
                if mac.upper() == "FF:FF:FF:FF:FF:FF":
                    continue

                baseline = DeviceBaseline(mac=mac, total_events=count)

                # ── Packet rate stats (per 5-min buckets) ────────────
                events = await db.execute(
                    select(WiFiEvent.timestamp)
                    .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
                    .order_by(WiFiEvent.timestamp)
                )
                timestamps = [row[0] for row in events.all()]
                if timestamps:
                    baseline.first_seen = timestamps[0]
                    baseline.last_seen = timestamps[-1]

                    # Bucket into 5-min windows and count
                    buckets = defaultdict(int)
                    for ts_str in timestamps:
                        try:
                            ts = datetime.fromisoformat(ts_str)
                            bucket_key = ts.strftime("%Y%m%d%H") + str(ts.minute // 5)
                            buckets[bucket_key] += 1
                        except (ValueError, TypeError):
                            continue

                    if buckets:
                        counts = list(buckets.values())
                        baseline.pkt_rate_avg = sum(counts) / len(counts)
                        if len(counts) > 1:
                            mean = baseline.pkt_rate_avg
                            variance = sum((x - mean) ** 2 for x in counts) / len(counts)
                            baseline.pkt_rate_std = variance ** 0.5
                        else:
                            baseline.pkt_rate_std = baseline.pkt_rate_avg * 0.3

                    # Active hours
                    for ts_str in timestamps:
                        try:
                            ts = datetime.fromisoformat(ts_str)
                            baseline.active_hours.add(ts.hour)
                        except (ValueError, TypeError):
                            continue

                # ── Frame type distribution ──────────────────────────
                ft_result = await db.execute(
                    select(WiFiEvent.frame_type, func.count(WiFiEvent.id))
                    .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
                    .group_by(WiFiEvent.frame_type)
                )
                ft_counts = {row[0]: row[1] for row in ft_result.all()}
                total_ft = sum(ft_counts.values()) or 1
                baseline.frame_dist = {ft: c / total_ft for ft, c in ft_counts.items()}

                # ── Destination diversity ────────────────────────────
                dest_result = await db.execute(
                    select(WiFiEvent.dst_mac)
                    .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
                )
                all_dests = [row[0] for row in dest_result.all()]
                baseline.known_dests = set(d for d in all_dests if d and d.upper() != "FF:FF:FF:FF:FF:FF")

                # Dest diversity per 5-min bucket
                dest_buckets = defaultdict(set)
                for i, ts_str in enumerate(timestamps):
                    if i < len(all_dests):
                        try:
                            ts = datetime.fromisoformat(ts_str)
                            bk = ts.strftime("%Y%m%d%H") + str(ts.minute // 5)
                            if all_dests[i] and all_dests[i].upper() != "FF:FF:FF:FF:FF:FF":
                                dest_buckets[bk].add(all_dests[i])
                        except (ValueError, TypeError):
                            continue

                if dest_buckets:
                    dest_counts = [len(v) for v in dest_buckets.values()]
                    baseline.dest_avg = sum(dest_counts) / len(dest_counts)
                    if len(dest_counts) > 1:
                        mean = baseline.dest_avg
                        baseline.dest_std = (sum((x - mean) ** 2 for x in dest_counts) / len(dest_counts)) ** 0.5
                    else:
                        baseline.dest_std = max(1.0, baseline.dest_avg * 0.3)

                # ── Channel spread ───────────────────────────────────
                chan_result = await db.execute(
                    select(WiFiEvent.channel)
                    .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
                )
                all_chans = [row[0] for row in chan_result.all()]

                chan_buckets = defaultdict(set)
                for i, ts_str in enumerate(timestamps):
                    if i < len(all_chans):
                        try:
                            ts = datetime.fromisoformat(ts_str)
                            bk = ts.strftime("%Y%m%d%H") + str(ts.minute // 5)
                            chan_buckets[bk].add(all_chans[i])
                        except (ValueError, TypeError):
                            continue

                if chan_buckets:
                    chan_counts = [len(v) for v in chan_buckets.values()]
                    baseline.chan_avg = sum(chan_counts) / len(chan_counts)
                    if len(chan_counts) > 1:
                        mean = baseline.chan_avg
                        baseline.chan_std = (sum((x - mean) ** 2 for x in chan_counts) / len(chan_counts)) ** 0.5
                    else:
                        baseline.chan_std = max(0.5, baseline.chan_avg * 0.3)

                self.baselines[mac] = baseline

            self._last_rebuild = time.time()
            print(f"[Profiler] Rebuilt baselines for {len(self.baselines)} devices")

    # ── Evaluate current behavior ────────────────────────────────────────

    async def evaluate_all(self) -> dict[str, DeviceRisk]:
        """Evaluate current behavior (last 5 min) against baselines."""
        async with async_session() as db:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=self.EVAL_WINDOW_MIN)).isoformat()
            now_hour = datetime.now(timezone.utc).hour

            # Get active devices in current window
            result = await db.execute(
                select(WiFiEvent.src_mac, func.count(WiFiEvent.id))
                .where(WiFiEvent.timestamp >= cutoff)
                .group_by(WiFiEvent.src_mac)
            )
            active_devices = {row[0]: row[1] for row in result.all()}

            new_risks: dict[str, DeviceRisk] = {}

            for mac, pkt_count in active_devices.items():
                if mac.upper() == "FF:FF:FF:FF:FF:FF":
                    continue

                baseline = self.baselines.get(mac)
                risk = DeviceRisk(mac=mac)

                # If no baseline yet, can't evaluate — just note it
                if not baseline or not baseline.is_mature():
                    risk.risk_score = 0
                    risk.reasons = ["Building baseline... (need more data)"]
                    new_risks[mac] = risk
                    continue

                # ── 1. Packet rate anomaly ───────────────────────────
                if baseline.pkt_rate_avg > 0:
                    ratio = pkt_count / max(baseline.pkt_rate_avg, 1)
                    threshold = baseline.pkt_rate_avg + 2 * max(baseline.pkt_rate_std, 1)
                    if pkt_count > threshold:
                        severity = min(1.0, (ratio - 1) / 4)  # caps at 5x
                        sub_score = int(severity * self.W_PACKET_RATE)
                        risk.risk_score += sub_score
                        risk.reasons.append(
                            f"Packet rate {ratio:.1f}x above normal "
                            f"({pkt_count}/5min vs baseline {baseline.pkt_rate_avg:.0f}/5min)"
                        )

                # ── 2. Active hours anomaly ──────────────────────────
                if baseline.active_hours and now_hour not in baseline.active_hours:
                    risk.risk_score += self.W_ACTIVE_HOURS
                    usual = sorted(baseline.active_hours)
                    start_h = usual[0] if usual else 0
                    end_h = usual[-1] if usual else 23
                    risk.reasons.append(
                        f"Active outside usual hours "
                        f"(now: {now_hour}:00, typical: {start_h}:00-{end_h}:00)"
                    )

                # ── 3. Frame type distribution anomaly ───────────────
                ft_result = await db.execute(
                    select(WiFiEvent.frame_type, func.count(WiFiEvent.id))
                    .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
                    .group_by(WiFiEvent.frame_type)
                )
                current_ft = {row[0]: row[1] for row in ft_result.all()}
                total_ft = sum(current_ft.values()) or 1
                current_dist = {ft: c / total_ft for ft, c in current_ft.items()}

                # Check for suspicious frame types spiking
                for ft, current_pct in current_dist.items():
                    baseline_pct = baseline.frame_dist.get(ft, 0.0)
                    # Flag if a frame type went from <5% to >20%
                    if current_pct > 0.20 and baseline_pct < 0.05:
                        severity = min(1.0, (current_pct - baseline_pct) / 0.5)
                        sub_score = int(severity * self.W_FRAME_DIST)
                        risk.risk_score += sub_score
                        risk.reasons.append(
                            f"Unusual frame type spike: '{ft}' is "
                            f"{current_pct*100:.0f}% of traffic "
                            f"(baseline: {baseline_pct*100:.0f}%)"
                        )

                # ── 4. Destination diversity anomaly ─────────────────
                dest_result = await db.execute(
                    select(func.count(distinct(WiFiEvent.dst_mac)))
                    .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
                )
                current_dest_count = dest_result.scalar() or 0

                if baseline.dest_avg > 0:
                    dest_threshold = baseline.dest_avg + 2 * max(baseline.dest_std, 1)
                    if current_dest_count > dest_threshold and current_dest_count > 5:
                        ratio = current_dest_count / max(baseline.dest_avg, 1)
                        severity = min(1.0, (ratio - 1) / 3)
                        sub_score = int(severity * self.W_DEST_DIVERSITY)
                        risk.risk_score += sub_score
                        risk.reasons.append(
                            f"Contacting {current_dest_count} destinations "
                            f"(baseline avg: {baseline.dest_avg:.0f})"
                        )

                # ── 5. New destination contacts ──────────────────────
                new_dest_result = await db.execute(
                    select(distinct(WiFiEvent.dst_mac))
                    .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
                )
                current_dests = set(row[0] for row in new_dest_result.all()
                                   if row[0] and row[0].upper() != "FF:FF:FF:FF:FF:FF")
                new_dests = current_dests - baseline.known_dests
                if len(new_dests) >= 3:
                    severity = min(1.0, len(new_dests) / 10)
                    sub_score = int(severity * self.W_NEW_DESTS)
                    risk.risk_score += sub_score
                    risk.reasons.append(
                        f"Contacting {len(new_dests)} never-before-seen destinations"
                    )

                # ── 6. Channel spread anomaly ────────────────────────
                chan_result = await db.execute(
                    select(func.count(distinct(WiFiEvent.channel)))
                    .where(WiFiEvent.src_mac == mac, WiFiEvent.timestamp >= cutoff)
                )
                current_chan_count = chan_result.scalar() or 0

                if baseline.chan_avg > 0:
                    chan_threshold = baseline.chan_avg + 2 * max(baseline.chan_std, 0.5)
                    if current_chan_count > chan_threshold and current_chan_count > 2:
                        severity = min(1.0, (current_chan_count - baseline.chan_avg) / 5)
                        sub_score = int(severity * self.W_CHANNEL_SPREAD)
                        risk.risk_score += sub_score
                        risk.reasons.append(
                            f"Seen on {current_chan_count} channels "
                            f"(baseline avg: {baseline.chan_avg:.1f})"
                        )

                # Cap at 100
                risk.risk_score = min(100, risk.risk_score)

                # If no anomalies found
                if not risk.reasons:
                    risk.reasons = ["Normal behavior"]

                new_risks[mac] = risk

            self.risks = new_risks
            return new_risks

    def get_all_risks(self) -> dict[str, dict]:
        """Return current risk data for all devices."""
        return {mac: r.to_dict() for mac, r in self.risks.items()}

    def get_risk(self, mac: str) -> dict | None:
        """Return risk data for a specific device."""
        r = self.risks.get(mac)
        return r.to_dict() if r else None
