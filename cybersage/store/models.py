"""SQLAlchemy models.

TODO: ``chunk`` (pgvector embeddings) and ``asset`` tables are deferred to a later phase.
"""

from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import (
    REAL,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

SOURCES = ("nvd", "kev", "epss", "osv")


class Base(DeclarativeBase):
    pass


class RawDocument(Base):
    """Raw source payload, kept alongside normalized records."""

    __tablename__ = "raw_documents"
    __table_args__ = (
        CheckConstraint("source IN ('nvd','kev','epss','osv')", name="ck_raw_documents_source"),
        UniqueConstraint("source", "source_key", "content_hash", name="uq_raw_documents_content"),
        Index("ix_raw_documents_lookup", "source", "source_key", "fetched_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(Text)
    source_key: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSONB)
    source_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Cve(Base):
    __tablename__ = "cve"
    __table_args__ = (
        Index("ix_cve_published_at", "published_at"),
        Index("ix_cve_last_modified_at", "last_modified_at"),
    )

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    raw_document_id: Mapped[int | None] = mapped_column(ForeignKey("raw_documents.id"))
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    vuln_status: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    cvss_version: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    cvss_severity: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSONB, server_default="[]")


class CveCwe(Base):
    __tablename__ = "cve_cwe"
    __table_args__ = (
        CheckConstraint("source IN ('nvd','osv')", name="ck_cve_cwe_source"),
        Index("ix_cve_cwe_cwe_id", "cwe_id"),
    )

    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cve.cve_id", ondelete="CASCADE"), primary_key=True
    )
    cwe_id: Mapped[str] = mapped_column(Text, primary_key=True)
    source: Mapped[str] = mapped_column(Text)


class AffectedPackage(Base):
    """Package-level affected data from OSV (or NVD-derived).

    Linked to CVEs through ``cve_aliases`` (no FK), since one OSV advisory may alias several
    CVEs and the CVE may not be stored locally.

    ``ranges`` holds OSV range objects. Ranges of type ``GIT`` are commit-hash based and are
    NOT matchable against a package version; the matcher must only use ``ECOSYSTEM`` and
    ``SEMVER`` ranges, plus the explicit ``versions`` list.
    """

    __tablename__ = "affected_package"
    __table_args__ = (
        CheckConstraint("source IN ('osv','nvd')", name="ck_affected_package_source"),
        CheckConstraint("ecosystem IN ('PyPI','npm')", name="ck_affected_package_ecosystem"),
        CheckConstraint(
            "confidence IN ('high','medium','low')", name="ck_affected_package_confidence"
        ),
        UniqueConstraint("source", "osv_id", "purl", name="uq_affected_package_source_osv_purl"),
        Index("ix_affected_package_ecosystem_name", "ecosystem", "package_name"),
        Index("ix_affected_package_purl", "purl"),
        Index("ix_affected_package_osv_id", "osv_id"),
        Index("ix_affected_package_cve_aliases", "cve_aliases", postgresql_using="gin"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    raw_document_id: Mapped[int | None] = mapped_column(ForeignKey("raw_documents.id"))
    source: Mapped[str] = mapped_column(Text)
    osv_id: Mapped[str] = mapped_column(Text)
    cve_aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    ecosystem: Mapped[str] = mapped_column(Text)
    package_name: Mapped[str] = mapped_column(Text)
    purl: Mapped[str] = mapped_column(Text)
    ranges: Mapped[list] = mapped_column(JSONB, server_default="[]")
    versions: Mapped[list] = mapped_column(JSONB, server_default="[]")
    fixed_version: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CpeApplicability(Base):
    __tablename__ = "cpe_applicability"
    __table_args__ = (
        Index("ix_cpe_applicability_cve_id", "cve_id"),
        Index("ix_cpe_applicability_vendor_product", "vendor", "product"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cve.cve_id", ondelete="CASCADE"))
    criteria: Mapped[str] = mapped_column(Text)
    vendor: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    vulnerable: Mapped[bool] = mapped_column(Boolean)
    version_start_including: Mapped[str | None] = mapped_column(Text)
    version_start_excluding: Mapped[str | None] = mapped_column(Text)
    version_end_including: Mapped[str | None] = mapped_column(Text)
    version_end_excluding: Mapped[str | None] = mapped_column(Text)
    node_index: Mapped[int | None] = mapped_column(Integer)


class Epss(Base):
    """No FK to cve: EPSS covers CVEs we do not store."""

    __tablename__ = "epss"
    __table_args__ = (
        Index("ix_epss_cve_id", "cve_id"),
        Index("ix_epss_score_date", "score_date"),
    )

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    score_date: Mapped[date] = mapped_column(Date, primary_key=True)
    epss: Mapped[float] = mapped_column(REAL)
    percentile: Mapped[float] = mapped_column(REAL)


class Kev(Base):
    """No FK to cve: KEV may list CVEs outside our scope."""

    __tablename__ = "kev"
    __table_args__ = (
        Index("ix_kev_cve_id", "cve_id"),
        Index("ix_kev_date_added", "date_added"),
    )

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    raw_document_id: Mapped[int | None] = mapped_column(ForeignKey("raw_documents.id"))
    vendor_project: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    vulnerability_name: Mapped[str | None] = mapped_column(Text)
    short_description: Mapped[str | None] = mapped_column(Text)
    required_action: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    date_added: Mapped[date] = mapped_column(Date)
    due_date: Mapped[date | None] = mapped_column(Date)
    known_ransomware_use: Mapped[bool | None] = mapped_column(Boolean)


class SyncState(Base):
    __tablename__ = "sync_state"

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    cursor: Mapped[dict | None] = mapped_column(JSONB)
    last_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(Text)
    last_error: Mapped[str | None] = mapped_column(Text)
