"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-10-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "raw_documents",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("source", sa.Text, nullable=False),
        sa.Column("source_key", sa.Text, nullable=False),
        sa.Column("content_hash", sa.Text, nullable=False),
        sa.Column("payload", pg.JSONB, nullable=False),
        sa.Column("source_modified_at", TZ),
        sa.Column("fetched_at", TZ, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("source IN ('nvd','kev','epss','osv')", name="ck_raw_documents_source"),
        sa.UniqueConstraint(
            "source", "source_key", "content_hash", name="uq_raw_documents_content"
        ),
    )
    op.create_index(
        "ix_raw_documents_lookup", "raw_documents", ["source", "source_key", "fetched_at"]
    )

    op.create_table(
        "cve",
        sa.Column("cve_id", sa.Text, primary_key=True),
        sa.Column("raw_document_id", sa.BigInteger, sa.ForeignKey("raw_documents.id")),
        sa.Column("published_at", TZ, nullable=False),
        sa.Column("last_modified_at", TZ, nullable=False),
        sa.Column("vuln_status", sa.Text),
        sa.Column("description", sa.Text),
        sa.Column("cvss_version", sa.Text),
        sa.Column("cvss_score", sa.Numeric(3, 1)),
        sa.Column("cvss_vector", sa.Text),
        sa.Column("cvss_severity", sa.Text),
        sa.Column("references", pg.JSONB, nullable=False, server_default="[]"),
    )
    op.create_index("ix_cve_published_at", "cve", ["published_at"])
    op.create_index("ix_cve_last_modified_at", "cve", ["last_modified_at"])

    op.create_table(
        "cve_cwe",
        sa.Column(
            "cve_id", sa.Text, sa.ForeignKey("cve.cve_id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column("cwe_id", sa.Text, primary_key=True),
        sa.Column("source", sa.Text, nullable=False),
        sa.CheckConstraint("source IN ('nvd','osv')", name="ck_cve_cwe_source"),
    )
    op.create_index("ix_cve_cwe_cwe_id", "cve_cwe", ["cwe_id"])

    op.create_table(
        "affected_package",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("raw_document_id", sa.BigInteger, sa.ForeignKey("raw_documents.id")),
        sa.Column("source", sa.Text, nullable=False),
        sa.Column("osv_id", sa.Text, nullable=False),
        sa.Column("cve_aliases", pg.ARRAY(sa.Text), nullable=False, server_default="{}"),
        sa.Column("ecosystem", sa.Text, nullable=False),
        sa.Column("package_name", sa.Text, nullable=False),
        sa.Column("purl", sa.Text, nullable=False),
        sa.Column("ranges", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("versions", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("fixed_version", sa.Text),
        sa.Column("confidence", sa.Text, nullable=False),
        sa.Column("created_at", TZ, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("source IN ('osv','nvd')", name="ck_affected_package_source"),
        sa.CheckConstraint("ecosystem IN ('PyPI','npm')", name="ck_affected_package_ecosystem"),
        sa.CheckConstraint(
            "confidence IN ('high','medium','low')", name="ck_affected_package_confidence"
        ),
        sa.UniqueConstraint("source", "osv_id", "purl", name="uq_affected_package_source_osv_purl"),
    )
    op.create_index(
        "ix_affected_package_ecosystem_name", "affected_package", ["ecosystem", "package_name"]
    )
    op.create_index("ix_affected_package_purl", "affected_package", ["purl"])
    op.create_index("ix_affected_package_osv_id", "affected_package", ["osv_id"])
    op.create_index(
        "ix_affected_package_cve_aliases",
        "affected_package",
        ["cve_aliases"],
        postgresql_using="gin",
    )

    op.create_table(
        "cpe_applicability",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "cve_id", sa.Text, sa.ForeignKey("cve.cve_id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("criteria", sa.Text, nullable=False),
        sa.Column("vendor", sa.Text),
        sa.Column("product", sa.Text),
        sa.Column("vulnerable", sa.Boolean, nullable=False),
        sa.Column("version_start_including", sa.Text),
        sa.Column("version_start_excluding", sa.Text),
        sa.Column("version_end_including", sa.Text),
        sa.Column("version_end_excluding", sa.Text),
        sa.Column("node_index", sa.Integer),
    )
    op.create_index("ix_cpe_applicability_cve_id", "cpe_applicability", ["cve_id"])
    op.create_index(
        "ix_cpe_applicability_vendor_product", "cpe_applicability", ["vendor", "product"]
    )

    op.create_table(
        "epss",
        sa.Column("cve_id", sa.Text, primary_key=True),
        sa.Column("score_date", sa.Date, primary_key=True),
        sa.Column("epss", sa.REAL, nullable=False),
        sa.Column("percentile", sa.REAL, nullable=False),
    )
    op.create_index("ix_epss_cve_id", "epss", ["cve_id"])
    op.create_index("ix_epss_score_date", "epss", ["score_date"])

    op.create_table(
        "kev",
        sa.Column("cve_id", sa.Text, primary_key=True),
        sa.Column("raw_document_id", sa.BigInteger, sa.ForeignKey("raw_documents.id")),
        sa.Column("vendor_project", sa.Text),
        sa.Column("product", sa.Text),
        sa.Column("vulnerability_name", sa.Text),
        sa.Column("short_description", sa.Text),
        sa.Column("required_action", sa.Text),
        sa.Column("notes", sa.Text),
        sa.Column("date_added", sa.Date, nullable=False),
        sa.Column("due_date", sa.Date),
        sa.Column("known_ransomware_use", sa.Boolean),
    )
    op.create_index("ix_kev_cve_id", "kev", ["cve_id"])
    op.create_index("ix_kev_date_added", "kev", ["date_added"])

    op.create_table(
        "sync_state",
        sa.Column("source", sa.Text, primary_key=True),
        sa.Column("cursor", pg.JSONB),
        sa.Column("last_started_at", TZ),
        sa.Column("last_success_at", TZ),
        sa.Column("last_status", sa.Text),
        sa.Column("last_error", sa.Text),
    )


def downgrade() -> None:
    for table in (
        "sync_state",
        "kev",
        "epss",
        "cpe_applicability",
        "affected_package",
        "cve_cwe",
        "cve",
        "raw_documents",
    ):
        op.drop_table(table)
