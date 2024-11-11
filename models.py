from sqlalchemy import Table, Column, Integer, String, Float, Boolean, DateTime, Index
from sqlalchemy.sql import func
from database import metadata
from sqlalchemy.dialects.postgresql import CIDR, INET

# Suspicious IP Ranges table
suspicious_ip_ranges = Table(
    "suspicious_ip_ranges",
    metadata,
    Column("cidr", CIDR, primary_key=True, nullable=False),
)

# Events table
events = Table(
    "events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column(
        "timestamp", DateTime(timezone=True), nullable=False, default=func.now()
    ),  # Timestamp of the event
    Column("username", String, nullable=False),
    Column("source_ip", INET, nullable=False),
    Column(
        "event_type", String, nullable=False
    ),
    Column(
        "file_size_mb", Float, nullable=True
    ),
    Column(
        "application", String, nullable=False
    ),
    Column("success", Boolean, nullable=False),
    Column(
        "is_suspicious", Boolean, nullable=False, default=False
    ),
    Index("ix_events_is_suspicious", "is_suspicious"),   # Indexed on is_supicious to speed up queries
)

# Tables for flagged users and flagged IPs
flagged_users = Table(
    "flagged_users", metadata, Column("user", String, primary_key=True)
)

flagged_ips = Table("flagged_ips", metadata, Column("ip", INET, primary_key=True))
