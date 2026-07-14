"""
PhantomSignal Data Models — The Bones of the Shadow Network

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict

from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, Enum as SAEnum,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    ABORTED = "aborted"


class ScanType(str, Enum):
    WEB_RECON = "web_recon"
    PEOPLE_INTEL = "people_intel"
    IP_RECON = "ip_recon"
    DOMAIN_RECON = "domain_recon"
    FULL_SPECTRUM = "full_spectrum"
    GHOST_RUN = "ghost_run"


class ThreatLevel(str, Enum):
    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


def _uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    """A scan — one complete recon run."""
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    target = Column(String(512), nullable=False)
    scan_type = Column(SAEnum(ScanType), default=ScanType.WEB_RECON)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    profile = Column(String(64), default="standard")
    modules_enabled = Column(JSON, default=list)
    options = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    progress = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    operator_notes = Column(Text, nullable=True)
    shadow_score = Column(Float, nullable=True)
    threat_level = Column(SAEnum(ThreatLevel), default=ThreatLevel.UNKNOWN)
    tags = Column(JSON, default=list)

    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")
    exports = relationship("Export", back_populates="scan", cascade="all, delete-orphan")

    @property
    def is_running(self) -> bool:
        return self.status == ScanStatus.RUNNING

    @property
    def result_count(self) -> int:
        return len(self.results)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "scan_type": self.scan_type.value if self.scan_type else None,
            "status": self.status.value if self.status else None,
            "profile": self.profile,
            "modules_enabled": self.modules_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "progress": self.progress,
            "error_message": self.error_message,
            "shadow_score": self.shadow_score,
            "threat_level": self.threat_level.value if self.threat_level else None,
            "tags": self.tags,
            "result_count": self.result_count,
        }


class ScanResult(Base):
    """A single data point found during a scan."""
    __tablename__ = "scan_results"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    module = Column(String(64), nullable=False)
    result_type = Column(String(64), nullable=False)
    source = Column(String(128), nullable=True)
    data = Column(JSON, nullable=False, default=dict)
    raw_data = Column(Text, nullable=True)
    confidence = Column(Float, default=1.0)
    relevance_score = Column(Float, default=0.5)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_anomaly = Column(Boolean, default=False)
    tags = Column(JSON, default=list)

    scan = relationship("Scan", back_populates="results")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "module": self.module,
            "result_type": self.result_type,
            "source": self.source,
            "data": self.data,
            "confidence": self.confidence,
            "relevance_score": self.relevance_score,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "is_anomaly": self.is_anomaly,
            "tags": self.tags,
        }


class ShadowProfile(Base):
    """Aggregated person intelligence — the full profile."""
    __tablename__ = "shadow_profiles"

    id = Column(String(36), primary_key=True, default=_uuid)
    full_name = Column(String(255), nullable=True)
    first_name = Column(String(128), nullable=True)
    last_name = Column(String(128), nullable=True)
    middle_name = Column(String(128), nullable=True)
    age = Column(Integer, nullable=True)
    dob = Column(String(32), nullable=True)
    gender = Column(String(16), nullable=True)
    emails = Column(JSON, default=list)
    phones = Column(JSON, default=list)
    addresses = Column(JSON, default=list)
    usernames = Column(JSON, default=list)
    social_profiles = Column(JSON, default=dict)
    employers = Column(JSON, default=list)
    education = Column(JSON, default=list)
    relatives = Column(JSON, default=list)
    associates = Column(JSON, default=list)
    breach_data = Column(JSON, default=list)
    images = Column(JSON, default=list)
    vehicles = Column(JSON, default=list)
    criminal_records = Column(JSON, default=list)
    court_records = Column(JSON, default=list)
    property_records = Column(JSON, default=list)
    sources = Column(JSON, default=list)
    shadow_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    raw_intel = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True)
    operator_notes = Column(Text, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "full_name": self.full_name,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "age": self.age,
            "dob": self.dob,
            "gender": self.gender,
            "emails": self.emails,
            "phones": self.phones,
            "addresses": self.addresses,
            "usernames": self.usernames,
            "social_profiles": self.social_profiles,
            "employers": self.employers,
            "education": self.education,
            "relatives": self.relatives,
            "associates": self.associates,
            "breach_data": self.breach_data,
            "sources": self.sources,
            "shadow_score": self.shadow_score,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class APIKeyStore(Base):
    """Encrypted API key store."""
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=_uuid)
    service = Column(String(64), unique=True, nullable=False)
    key_encrypted = Column(Text, nullable=False)
    label = Column(String(128), nullable=True)
    tier = Column(String(32), default="free")
    rate_limit_day = Column(Integer, nullable=True)
    rate_limit_month = Column(Integer, nullable=True)
    calls_today = Column(Integer, default=0)
    calls_month = Column(Integer, default=0)
    last_used = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    notes = Column(Text, nullable=True)


class Export(Base):
    """Intelligence packet export record."""
    __tablename__ = "exports"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    format = Column(String(16), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=True)
    compressed = Column(Boolean, default=False)
    encrypted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    checksum = Column(String(128), nullable=True)

    scan = relationship("Scan", back_populates="exports")


class ScheduledMission(Base):
    """A scheduled recurring scan."""
    __tablename__ = "scheduled_missions"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    target = Column(String(512), nullable=False)
    scan_type = Column(SAEnum(ScanType), default=ScanType.WEB_RECON)
    cron_expression = Column(String(64), nullable=False)
    modules_enabled = Column(JSON, default=list)
    options = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    run_count = Column(Integer, default=0)
    notify_on_complete = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ThreatIndicator(Base):
    """IOC — Indicator of compromise or interest."""
    __tablename__ = "threat_indicators"

    id = Column(String(36), primary_key=True, default=_uuid)
    indicator_type = Column(String(32), nullable=False)
    value = Column(String(512), nullable=False, index=True)
    threat_level = Column(SAEnum(ThreatLevel), default=ThreatLevel.UNKNOWN)
    confidence = Column(Float, default=0.5)
    sources = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    description = Column(Text, nullable=True)
    raw_data = Column(JSON, default=dict)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True)


# ── Geo / Locate (spec: specs/geo-locate.md) ─────────────────────────────────
class LocateCase(Base):
    """A person-locate investigation. Person geo work is always case-framed."""
    __tablename__ = "locate_cases"

    id = Column(String(36), primary_key=True, default=_uuid)
    subject = Column(String(255), nullable=True)          # display name
    identifiers = Column(JSON, default=dict)              # {first_name,last_name,email,username}
    purpose = Column(Text, nullable=True)                 # stated investigative purpose
    opened_by = Column(String(128), nullable=True)
    sensitivity = Column(String(16), default="normal")    # normal | minor
    status = Column(String(16), default="open")           # open | closed
    profile_id = Column(String(36), ForeignKey("shadow_profiles.id"), nullable=True)
    last_known = Column(JSON, nullable=True)              # cached aggregate
    retention_until = Column(String(32), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Deleting a case removes its signals + chain-of-custody so purged cases
    # leave nothing behind (spec §10 retention/purge).
    signals = relationship("LocateSignal", back_populates="case",
                           cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="case",
                                cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "subject": self.subject,
            "identifiers": self.identifiers or {},
            "purpose": self.purpose,
            "opened_by": self.opened_by,
            "sensitivity": self.sensitivity,
            "status": self.status,
            "last_known": self.last_known,
            "retention_until": self.retention_until,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class LocateSignal(Base):
    """A persisted GeoSignal under a case. Confidence stays compound — kind and
    attribution are stored separately and recombined at read time."""
    __tablename__ = "locate_signals"

    id = Column(String(36), primary_key=True, default=_uuid)
    case_id = Column(String(36), ForeignKey("locate_cases.id"), nullable=False, index=True)
    kind = Column(String(32), nullable=False)
    polarity = Column(String(8), default="positive")      # positive | negative
    entry = Column(String(8), default="auto")             # auto | manual
    place = Column(JSON, default=dict)                    # {city, region, country, zip}
    place_key = Column(String(128), nullable=True)
    lat = Column(Float, nullable=True)
    lon = Column(Float, nullable=True)
    observed_at = Column(String(32), nullable=True)
    source = Column(String(128), nullable=True)
    source_url = Column(String(512), nullable=True)
    attribution_confidence = Column(Float, default=1.0)
    raw = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("LocateCase", back_populates="signals")


class AuditEvent(Base):
    """Chain-of-custody: every ingest / edit / export against a case is logged."""
    __tablename__ = "locate_audit"

    id = Column(String(36), primary_key=True, default=_uuid)
    case_id = Column(String(36), ForeignKey("locate_cases.id"), nullable=False, index=True)
    actor = Column(String(128), nullable=True)
    action = Column(String(64), nullable=False)
    source = Column(String(128), nullable=True)
    detail = Column(Text, nullable=True)
    at = Column(DateTime, default=datetime.utcnow)

    case = relationship("LocateCase", back_populates="audit_events")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor": self.actor, "action": self.action, "source": self.source,
            "detail": self.detail, "at": self.at.isoformat() if self.at else None,
        }


class GeoCache(Base):
    """Persistent forward-geocode cache (spec §12 — Nominatim rate limits bite
    immediately). ``hit=False`` is a negative cache: a query we confirmed has no
    result, so we don't re-hit the geocoder for it."""
    __tablename__ = "geo_cache"

    query = Column(String(512), primary_key=True)
    lat = Column(Float, nullable=True)
    lon = Column(Float, nullable=True)
    hit = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
