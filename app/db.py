from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from .config import DB_PATH, DICTIONARY_DIR, ONTOLOGY_PATH, ROLE_ORDER
from .embeddings import EMBEDDING_DIMS, EMBEDDING_MODEL, embed_text, vector_to_blob
from .field_encryption import decrypt_field, encrypt_field


REQUIRED_DICTIONARY_FILES = (
    DICTIONARY_DIR / "domain_terms.json",
    DICTIONARY_DIR / "units.json",
)

REQUIRED_READY_COUNTS = (
    "sources",
    "documents",
    "entities",
    "facts",
    "graph_edges",
    "experiments",
    "experts",
)


@contextmanager
def connect(db_path: Path | str = DB_PATH):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    ensure_operational_schema(conn)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = {key: decrypt_field(value) if isinstance(value, str) else value for key, value in dict(row).items()}
    for key in (
        "aliases_json",
        "conditions_json",
        "metrics_json",
        "tags_json",
        "expertise_json",
        "metadata_json",
        "result_json",
        "details_json",
        "resource_json",
        "external_json",
        "classifications_json",
        "emails_json",
        "validation_warnings_json",
        "headers_json",
        "rows_json",
    ):
        if key in result and isinstance(result[key], str):
            try:
                result[key.replace("_json", "")] = json.loads(result[key])
            except json.JSONDecodeError:
                pass
    return result


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [row_to_dict(row) for row in rows if row is not None]


def default_chunk_locator(chunk_no: int) -> tuple[str, str, dict[str, int]]:
    chunk_index = int(chunk_no) + 1
    return "chunk", f"chunk {chunk_index}", {"chunk": chunk_index}


def _normalize_document_locator(
    chunk_no: int,
    locator_type: str | None,
    locator: str | None,
    metadata: dict[str, Any] | None,
) -> tuple[str | None, str | None, dict[str, Any]]:
    normalized_metadata = dict(metadata or {})
    if locator:
        return locator_type, locator, normalized_metadata
    fallback_type, fallback_locator, fallback_metadata = default_chunk_locator(chunk_no)
    for key, value in fallback_metadata.items():
        normalized_metadata.setdefault(key, value)
    return locator_type or fallback_type, fallback_locator, normalized_metadata


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        DROP TABLE IF EXISTS documents_fts;
        DROP TABLE IF EXISTS document_embeddings;
        DROP TABLE IF EXISTS export_approvals;
        DROP TABLE IF EXISTS policy_decisions;
        DROP TABLE IF EXISTS directory_group_members;
        DROP TABLE IF EXISTS directory_groups;
        DROP TABLE IF EXISTS directory_users;
        DROP TABLE IF EXISTS audit_log;
        DROP TABLE IF EXISTS ingest_files;
        DROP TABLE IF EXISTS graph_edges;
        DROP TABLE IF EXISTS fact_dispute_comments;
        DROP TABLE IF EXISTS fact_disputes;
        DROP TABLE IF EXISTS fact_assignments;
        DROP TABLE IF EXISTS fact_reviews;
        DROP TABLE IF EXISTS facts;
        DROP TABLE IF EXISTS experiments;
        DROP TABLE IF EXISTS document_tables;
        DROP TABLE IF EXISTS documents;
        DROP TABLE IF EXISTS sources;
        DROP TABLE IF EXISTS experts;
        DROP TABLE IF EXISTS entities;

        CREATE TABLE sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            source_type TEXT NOT NULL,
            language TEXT,
            geography TEXT,
            additional_geography TEXT,
            year INTEGER,
            date TEXT,
            reliability_score REAL DEFAULT 0.5,
            confidentiality TEXT DEFAULT 'internal',
            path TEXT,
            abstract TEXT,
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            chunk_no INTEGER NOT NULL,
            text TEXT NOT NULL,
            locator_type TEXT,
            locator TEXT,
            start_char INTEGER,
            end_char INTEGER,
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE VIRTUAL TABLE documents_fts USING fts5(
            text,
            source_id UNINDEXED,
            doc_id UNINDEXED,
            tokenize='unicode61 remove_diacritics 2'
        );

        CREATE TABLE document_embeddings (
            document_id INTEGER PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
            source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            model TEXT NOT NULL,
            dims INTEGER NOT NULL,
            vector_blob BLOB NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            aliases_json TEXT DEFAULT '[]',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(type, normalized_name)
        );

        CREATE TABLE facts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
            subject_id INTEGER REFERENCES entities(id) ON DELETE SET NULL,
            predicate TEXT NOT NULL,
            object_id INTEGER REFERENCES entities(id) ON DELETE SET NULL,
            property TEXT,
            comparator TEXT,
            numeric_value REAL,
            min_value REAL,
            max_value REAL,
            unit TEXT,
            value_text TEXT,
            confidence REAL DEFAULT 0.5,
            extraction_confidence REAL DEFAULT 0.5,
            validation_status TEXT DEFAULT 'valid',
            validation_warnings_json TEXT DEFAULT '[]',
            status TEXT DEFAULT 'candidate',
            version INTEGER DEFAULT 1,
            supersedes_fact_id INTEGER REFERENCES facts(id) ON DELETE SET NULL,
            document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL,
            evidence TEXT,
            evidence_locator TEXT,
            evidence_start INTEGER,
            evidence_end INTEGER,
            extractor_version TEXT DEFAULT 'dictionary-regex-v1',
            valid_from TEXT,
            valid_to TEXT,
            asserted_by TEXT DEFAULT 'auto-extractor',
            asserted_at TEXT DEFAULT CURRENT_TIMESTAMP,
            verified_by TEXT,
            verified_at TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE fact_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fact_id INTEGER NOT NULL REFERENCES facts(id) ON DELETE CASCADE,
            reviewer TEXT,
            role TEXT,
            action TEXT NOT NULL,
            comment TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE fact_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fact_id INTEGER NOT NULL REFERENCES facts(id) ON DELETE CASCADE,
            assignee TEXT NOT NULL,
            assigned_by TEXT,
            role TEXT,
            status TEXT DEFAULT 'active',
            due_at TEXT,
            comment TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            released_at TEXT
        );

        CREATE TABLE fact_disputes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fact_id INTEGER NOT NULL REFERENCES facts(id) ON DELETE CASCADE,
            opened_by TEXT,
            role TEXT,
            severity TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'open',
            reason TEXT NOT NULL,
            assignee TEXT,
            due_at TEXT,
            escalated_at TEXT,
            resolved_by TEXT,
            resolved_at TEXT,
            resolution TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE fact_dispute_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dispute_id INTEGER NOT NULL REFERENCES fact_disputes(id) ON DELETE CASCADE,
            author TEXT,
            role TEXT,
            comment TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE graph_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
            subject_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            predicate TEXT NOT NULL,
            object_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            confidence REAL DEFAULT 0.5,
            evidence TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(source_id, subject_id, predicate, object_id, evidence)
        );

        CREATE TABLE experiments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            experiment_key TEXT UNIQUE,
            source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
            title TEXT NOT NULL,
            year INTEGER,
            geography TEXT,
            material TEXT,
            process TEXT,
            conditions_json TEXT DEFAULT '{}',
            metrics_json TEXT DEFAULT '{}',
            result_summary TEXT,
            reliability_score REAL DEFAULT 0.5,
            team TEXT
        );

        CREATE TABLE document_tables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL,
            locator TEXT,
            table_type TEXT DEFAULT 'detected',
            headers_json TEXT DEFAULT '[]',
            rows_json TEXT DEFAULT '[]',
            confidence REAL DEFAULT 0.5,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE experts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            organization TEXT,
            geography TEXT,
            expertise_json TEXT DEFAULT '[]',
            contact TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT,
            role TEXT,
            action TEXT NOT NULL,
            object_type TEXT,
            object_id TEXT,
            details_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE export_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester TEXT,
            requester_role TEXT NOT NULL,
            action TEXT NOT NULL,
            export_format TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT,
            payload_hash TEXT NOT NULL,
            max_confidentiality TEXT NOT NULL,
            classifications_json TEXT DEFAULT '[]',
            reason TEXT,
            justification TEXT,
            status TEXT DEFAULT 'pending',
            requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
            reviewed_by TEXT,
            reviewer_role TEXT,
            reviewed_at TEXT,
            review_comment TEXT,
            consumed_at TEXT,
            expires_at TEXT
        );

        CREATE TABLE policy_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            allowed INTEGER NOT NULL,
            reason TEXT,
            source TEXT,
            role TEXT,
            subject TEXT,
            department TEXT,
            project TEXT,
            clearance TEXT,
            auth_method TEXT,
            resource_json TEXT DEFAULT '{}',
            external_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE directory_users (
            id TEXT PRIMARY KEY,
            user_name TEXT NOT NULL UNIQUE,
            display_name TEXT,
            role TEXT,
            department TEXT,
            project TEXT,
            clearance TEXT,
            active INTEGER DEFAULT 1,
            external_id TEXT,
            emails_json TEXT DEFAULT '[]',
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            deactivated_at TEXT
        );

        CREATE TABLE directory_groups (
            id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL UNIQUE,
            role TEXT,
            external_id TEXT,
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE directory_group_members (
            group_id TEXT NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES directory_users(id) ON DELETE CASCADE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(group_id, user_id)
        );

        CREATE TABLE ingest_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL UNIQUE,
            suffix TEXT,
            size_bytes INTEGER,
            checksum TEXT,
            status TEXT NOT NULL,
            source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
            error TEXT,
            result_json TEXT DEFAULT '{}',
            queued_at TEXT DEFAULT CURRENT_TIMESTAMP,
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX idx_sources_year ON sources(year);
        CREATE INDEX idx_sources_geo ON sources(geography);
        CREATE INDEX idx_sources_conf ON sources(confidentiality);
        CREATE INDEX idx_document_embeddings_source ON document_embeddings(source_id);
        CREATE INDEX idx_entities_norm ON entities(normalized_name);
        CREATE INDEX idx_facts_property ON facts(property);
        CREATE INDEX idx_facts_source ON facts(source_id);
        CREATE INDEX idx_facts_status ON facts(status);
        CREATE INDEX idx_facts_status_confidence ON facts(status, confidence DESC, id DESC);
        CREATE INDEX idx_facts_document ON facts(document_id);
        CREATE INDEX idx_facts_subject ON facts(subject_id);
        CREATE INDEX idx_facts_object ON facts(object_id);
        CREATE INDEX idx_facts_numeric ON facts(property, min_value, max_value, numeric_value, unit);
        CREATE INDEX idx_graph_edges_source ON graph_edges(source_id);
        CREATE INDEX idx_graph_edges_subject ON graph_edges(subject_id);
        CREATE INDEX idx_graph_edges_object ON graph_edges(object_id);
        CREATE INDEX idx_graph_edges_predicate ON graph_edges(predicate);
        CREATE INDEX idx_fact_reviews_fact ON fact_reviews(fact_id);
        CREATE UNIQUE INDEX idx_fact_assignments_active_fact ON fact_assignments(fact_id) WHERE status = 'active';
        CREATE INDEX idx_fact_assignments_assignee ON fact_assignments(assignee, status, due_at);
        CREATE INDEX idx_document_tables_source ON document_tables(source_id);
        CREATE INDEX idx_experiments_year ON experiments(year);
        CREATE INDEX idx_experiments_geo ON experiments(geography);
        CREATE INDEX idx_experiments_process ON experiments(process);
        CREATE INDEX idx_ingest_files_status ON ingest_files(status);
        CREATE INDEX idx_ingest_files_suffix ON ingest_files(suffix);
        CREATE INDEX idx_export_approvals_status ON export_approvals(status, requested_at);
        CREATE INDEX idx_export_approvals_payload ON export_approvals(payload_hash, export_format, object_type, object_id);
        CREATE INDEX idx_policy_decisions_action ON policy_decisions(action, created_at);
        CREATE INDEX idx_policy_decisions_allowed ON policy_decisions(allowed, created_at);
        CREATE INDEX idx_policy_decisions_source ON policy_decisions(source, created_at);
        CREATE INDEX idx_directory_users_user_name ON directory_users(user_name);
        CREATE INDEX idx_directory_users_external_id ON directory_users(external_id);
        CREATE INDEX idx_directory_users_active ON directory_users(active);
        CREATE INDEX idx_directory_groups_external_id ON directory_groups(external_id);
        CREATE INDEX idx_directory_group_members_user ON directory_group_members(user_id);
        """
    )


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _column_exists(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    if not _table_exists(conn, table_name):
        return False
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row["name"] == column_name for row in rows)


def ensure_operational_schema(conn: sqlite3.Connection) -> None:
    if _table_exists(conn, "documents"):
        document_columns = {
            "locator_type": "TEXT",
            "locator": "TEXT",
            "start_char": "INTEGER",
            "end_char": "INTEGER",
            "metadata_json": "TEXT DEFAULT '{}'",
        }
        for column, definition in document_columns.items():
            if not _column_exists(conn, "documents", column):
                conn.execute(f"ALTER TABLE documents ADD COLUMN {column} {definition}")

    if _table_exists(conn, "facts"):
        fact_columns = {
            "validation_status": "TEXT DEFAULT 'valid'",
            "validation_warnings_json": "TEXT DEFAULT '[]'",
            "document_id": "INTEGER REFERENCES documents(id) ON DELETE SET NULL",
            "evidence_locator": "TEXT",
            "evidence_start": "INTEGER",
            "evidence_end": "INTEGER",
            "extractor_version": "TEXT DEFAULT 'dictionary-regex-v1'",
        }
        for column, definition in fact_columns.items():
            if not _column_exists(conn, "facts", column):
                conn.execute(f"ALTER TABLE facts ADD COLUMN {column} {definition}")

    if _table_exists(conn, "sources") and _table_exists(conn, "documents"):
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS document_tables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
                document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL,
                locator TEXT,
                table_type TEXT DEFAULT 'detected',
                headers_json TEXT DEFAULT '[]',
                rows_json TEXT DEFAULT '[]',
                confidence REAL DEFAULT 0.5,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS document_embeddings (
                document_id INTEGER PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
                source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
                model TEXT NOT NULL,
                dims INTEGER NOT NULL,
                vector_blob BLOB NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_facts_document ON facts(document_id);
            CREATE INDEX IF NOT EXISTS idx_facts_source ON facts(source_id);
            CREATE INDEX IF NOT EXISTS idx_facts_status_confidence ON facts(status, confidence DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_facts_subject ON facts(subject_id);
            CREATE INDEX IF NOT EXISTS idx_facts_object ON facts(object_id);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_id);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_subject ON graph_edges(subject_id);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_object ON graph_edges(object_id);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_predicate ON graph_edges(predicate);
            CREATE INDEX IF NOT EXISTS idx_document_tables_source ON document_tables(source_id);
            CREATE INDEX IF NOT EXISTS idx_document_embeddings_source ON document_embeddings(source_id);
            CREATE TABLE IF NOT EXISTS fact_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fact_id INTEGER NOT NULL REFERENCES facts(id) ON DELETE CASCADE,
                assignee TEXT NOT NULL,
                assigned_by TEXT,
                role TEXT,
                status TEXT DEFAULT 'active',
                due_at TEXT,
                comment TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                released_at TEXT
            );
            CREATE TABLE IF NOT EXISTS fact_disputes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fact_id INTEGER NOT NULL REFERENCES facts(id) ON DELETE CASCADE,
                opened_by TEXT,
                role TEXT,
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                reason TEXT NOT NULL,
                assignee TEXT,
                due_at TEXT,
                escalated_at TEXT,
                resolved_by TEXT,
                resolved_at TEXT,
                resolution TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS fact_dispute_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dispute_id INTEGER NOT NULL REFERENCES fact_disputes(id) ON DELETE CASCADE,
                author TEXT,
                role TEXT,
                comment TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_fact_assignments_active_fact ON fact_assignments(fact_id) WHERE status = 'active';
            CREATE INDEX IF NOT EXISTS idx_fact_assignments_assignee ON fact_assignments(assignee, status, due_at);
            CREATE INDEX IF NOT EXISTS idx_fact_disputes_fact ON fact_disputes(fact_id, status);
            CREATE INDEX IF NOT EXISTS idx_fact_disputes_status_due ON fact_disputes(status, due_at);
            CREATE INDEX IF NOT EXISTS idx_fact_dispute_comments_dispute ON fact_dispute_comments(dispute_id);
            """
        )
    ensure_audit_schema(conn)
    ensure_export_approval_schema(conn)
    ensure_policy_decision_schema(conn)
    ensure_directory_schema(conn)


def ensure_audit_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT,
            role TEXT,
            action TEXT NOT NULL,
            object_type TEXT,
            object_id TEXT,
            details_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def ensure_export_approval_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS export_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester TEXT,
            requester_role TEXT NOT NULL,
            action TEXT NOT NULL,
            export_format TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT,
            payload_hash TEXT NOT NULL,
            max_confidentiality TEXT NOT NULL,
            classifications_json TEXT DEFAULT '[]',
            reason TEXT,
            justification TEXT,
            status TEXT DEFAULT 'pending',
            requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
            reviewed_by TEXT,
            reviewer_role TEXT,
            reviewed_at TEXT,
            review_comment TEXT,
            consumed_at TEXT,
            expires_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_export_approvals_status ON export_approvals(status, requested_at);
        CREATE INDEX IF NOT EXISTS idx_export_approvals_payload ON export_approvals(payload_hash, export_format, object_type, object_id);
        """
    )


def ensure_policy_decision_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS policy_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            allowed INTEGER NOT NULL,
            reason TEXT,
            source TEXT,
            role TEXT,
            subject TEXT,
            department TEXT,
            project TEXT,
            clearance TEXT,
            auth_method TEXT,
            resource_json TEXT DEFAULT '{}',
            external_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_policy_decisions_action ON policy_decisions(action, created_at);
        CREATE INDEX IF NOT EXISTS idx_policy_decisions_allowed ON policy_decisions(allowed, created_at);
        CREATE INDEX IF NOT EXISTS idx_policy_decisions_source ON policy_decisions(source, created_at);
        """
    )


def ensure_directory_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS directory_users (
            id TEXT PRIMARY KEY,
            user_name TEXT NOT NULL UNIQUE,
            display_name TEXT,
            role TEXT,
            department TEXT,
            project TEXT,
            clearance TEXT,
            active INTEGER DEFAULT 1,
            external_id TEXT,
            emails_json TEXT DEFAULT '[]',
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            deactivated_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS directory_groups (
            id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL UNIQUE,
            role TEXT,
            external_id TEXT,
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS directory_group_members (
            group_id TEXT NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES directory_users(id) ON DELETE CASCADE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(group_id, user_id)
        )
        """
    )
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_directory_users_user_name ON directory_users(user_name)",
        "CREATE INDEX IF NOT EXISTS idx_directory_users_external_id ON directory_users(external_id)",
        "CREATE INDEX IF NOT EXISTS idx_directory_users_active ON directory_users(active)",
        "CREATE INDEX IF NOT EXISTS idx_directory_groups_external_id ON directory_groups(external_id)",
        "CREATE INDEX IF NOT EXISTS idx_directory_group_members_user ON directory_group_members(user_id)",
    ):
        conn.execute(statement)


def readiness_report(db_path: Path | str = DB_PATH) -> dict[str, Any]:
    path = Path(db_path)
    dictionary_files = {str(file): file.exists() for file in REQUIRED_DICTIONARY_FILES}
    report: dict[str, Any] = {
        "ready": False,
        "db_path": str(path),
        "db_exists": path.exists(),
        "dictionary_files": dictionary_files,
        "ontology_file": {str(ONTOLOGY_PATH): ONTOLOGY_PATH.exists()},
        "tables": {},
        "counts": {},
        "fts_count": None,
        "embedding_count": None,
        "embedding_coverage": None,
        "issues": [],
    }
    if not all(dictionary_files.values()):
        missing = [file for file, exists in dictionary_files.items() if not exists]
        report["issues"].append(f"Missing dictionary files: {', '.join(missing)}")
    if not ONTOLOGY_PATH.exists():
        report["issues"].append(f"Missing ontology file: {ONTOLOGY_PATH}")
    if not path.exists():
        report["issues"].append("Database file does not exist")
        return report

    try:
        with connect(path) as conn:
            ensure_operational_schema(conn)
            required_tables = set(REQUIRED_READY_COUNTS) | {"documents_fts"}
            for table in sorted(required_tables):
                exists = _table_exists(conn, table)
                report["tables"][table] = exists
                if not exists:
                    report["issues"].append(f"Missing table: {table}")
            if all(report["tables"].values()):
                for table in REQUIRED_READY_COUNTS:
                    count = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                    report["counts"][table] = count
                    if count <= 0:
                        report["issues"].append(f"Table {table} is empty")
                fts_count = int(conn.execute("SELECT COUNT(*) FROM documents_fts").fetchone()[0])
                report["fts_count"] = fts_count
                if fts_count <= 0:
                    report["issues"].append("FTS index is empty")
                if _table_exists(conn, "document_embeddings"):
                    embedding_count = int(conn.execute("SELECT COUNT(*) FROM document_embeddings").fetchone()[0])
                    document_count = int(report["counts"].get("documents") or 0)
                    report["embedding_count"] = embedding_count
                    report["embedding_coverage"] = round(embedding_count / document_count, 6) if document_count else 0.0
    except Exception as exc:
        report["issues"].append(f"Database readiness check failed: {exc}")

    report["ready"] = not report["issues"]
    return report


def is_database_ready(db_path: Path | str = DB_PATH) -> bool:
    return bool(readiness_report(db_path).get("ready"))


def insert_audit(conn: sqlite3.Connection, action: str, role: str, actor: str = "demo-user", object_type: str | None = None, object_id: str | None = None, details: dict[str, Any] | None = None) -> None:
    ensure_audit_schema(conn)
    details_json = json.dumps(details or {}, ensure_ascii=False)
    conn.execute(
        """
        INSERT INTO audit_log(actor, role, action, object_type, object_id, details_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (actor, role, action, object_type, encrypt_field(object_id), encrypt_field(details_json)),
    )


def insert_policy_decision(
    conn: sqlite3.Connection,
    *,
    action: str,
    allowed: bool,
    reason: str,
    source: str,
    role: str,
    subject: str | None = None,
    department: str | None = None,
    project: str | None = None,
    clearance: str | None = None,
    auth_method: str | None = None,
    resource: dict[str, Any] | None = None,
    external: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ensure_policy_decision_schema(conn)
    cursor = conn.execute(
        """
        INSERT INTO policy_decisions(
            action, allowed, reason, source, role, subject, department, project,
            clearance, auth_method, resource_json, external_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            action,
            1 if allowed else 0,
            encrypt_field(reason),
            source,
            role,
            subject,
            department,
            project,
            clearance,
            auth_method,
            encrypt_field(json.dumps(resource or {}, ensure_ascii=False)),
            encrypt_field(json.dumps(external or {}, ensure_ascii=False)),
        ),
    )
    row = conn.execute("SELECT * FROM policy_decisions WHERE id = ?", (int(cursor.lastrowid),)).fetchone()
    return row_to_dict(row) or {}


def list_policy_decisions(
    conn: sqlite3.Connection,
    *,
    action: str | None = None,
    allowed: bool | None = None,
    source: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    ensure_policy_decision_schema(conn)
    capped_limit = max(1, min(int(limit), 500))
    where: list[str] = []
    values: list[Any] = []
    if action:
        where.append("action = ?")
        values.append(action)
    if allowed is not None:
        where.append("allowed = ?")
        values.append(1 if allowed else 0)
    if source:
        where.append("source = ?")
        values.append(source)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    rows = conn.execute(
        f"SELECT * FROM policy_decisions {clause} ORDER BY id DESC LIMIT ?",
        values + [capped_limit],
    ).fetchall()
    return rows_to_dicts(rows)


def _validate_directory_role(role: str | None) -> str | None:
    if role in {None, ""}:
        return None
    normalized = str(role).strip()
    if normalized not in ROLE_ORDER:
        raise ValueError(f"Unknown directory role: {role}")
    return normalized


def upsert_directory_user(
    conn: sqlite3.Connection,
    *,
    user_id: str,
    user_name: str | None = None,
    display_name: str | None = None,
    role: str | None = None,
    department: str | None = None,
    project: str | None = None,
    clearance: str | None = None,
    active: bool = True,
    external_id: str | None = None,
    emails: list[Any] | None = None,
    metadata: dict[str, Any] | None = None,
    actor: str = "directory-sync",
    actor_role: str = "admin",
    audit: bool = True,
) -> dict[str, Any]:
    ensure_directory_schema(conn)
    normalized_id = str(user_id or user_name or external_id or "").strip()
    normalized_user_name = str(user_name or normalized_id).strip()
    if not normalized_id:
        raise ValueError("directory user_id is required")
    if not normalized_user_name:
        raise ValueError("directory user_name is required")
    normalized_role = _validate_directory_role(role)
    active_int = 1 if active else 0
    conn.execute(
        """
        INSERT INTO directory_users(
            id, user_name, display_name, role, department, project, clearance,
            active, external_id, emails_json, metadata_json, updated_at, deactivated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CASE WHEN ? = 0 THEN CURRENT_TIMESTAMP ELSE NULL END)
        ON CONFLICT(id) DO UPDATE SET
            user_name = excluded.user_name,
            display_name = excluded.display_name,
            role = excluded.role,
            department = excluded.department,
            project = excluded.project,
            clearance = excluded.clearance,
            active = excluded.active,
            external_id = excluded.external_id,
            emails_json = excluded.emails_json,
            metadata_json = excluded.metadata_json,
            updated_at = CURRENT_TIMESTAMP,
            deactivated_at = CASE
                WHEN excluded.active = 0 THEN COALESCE(directory_users.deactivated_at, CURRENT_TIMESTAMP)
                ELSE NULL
            END
        """,
        (
            normalized_id,
            normalized_user_name,
            display_name,
            normalized_role,
            department,
            project,
            clearance,
            active_int,
            external_id,
            encrypt_field(json.dumps(emails or [], ensure_ascii=False)),
            json.dumps(metadata or {}, ensure_ascii=False),
            active_int,
        ),
    )
    if audit:
        insert_audit(
            conn,
            "directory_user_upsert",
            actor_role,
            actor=actor,
            object_type="directory_user",
            object_id=normalized_id,
            details={
                "user_name": normalized_user_name,
                "role": normalized_role,
                "department": department,
                "project": project,
                "clearance": clearance,
                "active": bool(active),
            },
        )
    user = get_directory_user(conn, normalized_id)
    if user is None:
        raise KeyError(f"Directory user not found after upsert: {normalized_id}")
    return user


def get_directory_user(conn: sqlite3.Connection, subject: str) -> dict[str, Any] | None:
    ensure_directory_schema(conn)
    normalized = str(subject).strip()
    if not normalized:
        return None
    row = conn.execute(
        """
        SELECT *
        FROM directory_users
        WHERE id = ? OR user_name = ? OR external_id = ?
        ORDER BY CASE WHEN id = ? THEN 0 WHEN user_name = ? THEN 1 ELSE 2 END
        LIMIT 1
        """,
        (normalized, normalized, normalized, normalized, normalized),
    ).fetchone()
    return row_to_dict(row)


def list_directory_users(conn: sqlite3.Connection, *, active: bool | None = None, limit: int = 100, start_index: int = 1) -> list[dict[str, Any]]:
    ensure_directory_schema(conn)
    capped_limit = max(1, min(int(limit), 500))
    offset = max(0, int(start_index) - 1)
    if active is None:
        rows = conn.execute(
            "SELECT * FROM directory_users ORDER BY user_name LIMIT ? OFFSET ?",
            (capped_limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM directory_users WHERE active = ? ORDER BY user_name LIMIT ? OFFSET ?",
            (1 if active else 0, capped_limit, offset),
        ).fetchall()
    return rows_to_dicts(rows)


def count_directory_users(conn: sqlite3.Connection, *, active: bool | None = None) -> int:
    ensure_directory_schema(conn)
    if active is None:
        return int(conn.execute("SELECT COUNT(*) FROM directory_users").fetchone()[0])
    return int(conn.execute("SELECT COUNT(*) FROM directory_users WHERE active = ?", (1 if active else 0,)).fetchone()[0])


def deactivate_directory_user(
    conn: sqlite3.Connection,
    user_id: str,
    *,
    actor: str = "directory-sync",
    actor_role: str = "admin",
    audit: bool = True,
) -> dict[str, Any]:
    ensure_directory_schema(conn)
    user = get_directory_user(conn, user_id)
    if user is None:
        raise KeyError(f"Directory user not found: {user_id}")
    conn.execute(
        """
        UPDATE directory_users
        SET active = 0,
            deactivated_at = COALESCE(deactivated_at, CURRENT_TIMESTAMP),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (user["id"],),
    )
    if audit:
        insert_audit(
            conn,
            "directory_user_deactivate",
            actor_role,
            actor=actor,
            object_type="directory_user",
            object_id=user["id"],
            details={"user_name": user.get("user_name")},
        )
    deactivated = get_directory_user(conn, user["id"])
    if deactivated is None:
        raise KeyError(f"Directory user not found after deactivate: {user_id}")
    return deactivated


def upsert_directory_group(
    conn: sqlite3.Connection,
    *,
    group_id: str,
    display_name: str | None = None,
    role: str | None = None,
    external_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    actor: str = "directory-sync",
    actor_role: str = "admin",
    audit: bool = True,
) -> dict[str, Any]:
    ensure_directory_schema(conn)
    normalized_id = str(group_id or display_name or external_id or "").strip()
    normalized_display_name = str(display_name or normalized_id).strip()
    if not normalized_id:
        raise ValueError("directory group_id is required")
    if not normalized_display_name:
        raise ValueError("directory group display_name is required")
    normalized_role = _validate_directory_role(role)
    conn.execute(
        """
        INSERT INTO directory_groups(id, display_name, role, external_id, metadata_json, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            display_name = excluded.display_name,
            role = excluded.role,
            external_id = excluded.external_id,
            metadata_json = excluded.metadata_json,
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            normalized_id,
            normalized_display_name,
            normalized_role,
            external_id,
            json.dumps(metadata or {}, ensure_ascii=False),
        ),
    )
    if audit:
        insert_audit(
            conn,
            "directory_group_upsert",
            actor_role,
            actor=actor,
            object_type="directory_group",
            object_id=normalized_id,
            details={"display_name": normalized_display_name, "role": normalized_role},
        )
    group = get_directory_group(conn, normalized_id)
    if group is None:
        raise KeyError(f"Directory group not found after upsert: {normalized_id}")
    return group


def get_directory_group(conn: sqlite3.Connection, group_id: str) -> dict[str, Any] | None:
    ensure_directory_schema(conn)
    normalized = str(group_id).strip()
    if not normalized:
        return None
    row = conn.execute(
        """
        SELECT *
        FROM directory_groups
        WHERE id = ? OR display_name = ? OR external_id = ?
        ORDER BY CASE WHEN id = ? THEN 0 WHEN display_name = ? THEN 1 ELSE 2 END
        LIMIT 1
        """,
        (normalized, normalized, normalized, normalized, normalized),
    ).fetchone()
    return row_to_dict(row)


def list_directory_groups(conn: sqlite3.Connection, *, limit: int = 100, start_index: int = 1) -> list[dict[str, Any]]:
    ensure_directory_schema(conn)
    capped_limit = max(1, min(int(limit), 500))
    offset = max(0, int(start_index) - 1)
    rows = conn.execute(
        "SELECT * FROM directory_groups ORDER BY display_name LIMIT ? OFFSET ?",
        (capped_limit, offset),
    ).fetchall()
    return rows_to_dicts(rows)


def count_directory_groups(conn: sqlite3.Connection) -> int:
    ensure_directory_schema(conn)
    return int(conn.execute("SELECT COUNT(*) FROM directory_groups").fetchone()[0])


def replace_directory_group_members(
    conn: sqlite3.Connection,
    group_id: str,
    user_ids: list[str],
    *,
    actor: str = "directory-sync",
    actor_role: str = "admin",
    audit: bool = True,
) -> list[dict[str, Any]]:
    ensure_directory_schema(conn)
    group = get_directory_group(conn, group_id)
    if group is None:
        raise KeyError(f"Directory group not found: {group_id}")
    resolved_user_ids: list[str] = []
    for user_id in dict.fromkeys(str(item).strip() for item in user_ids if str(item).strip()):
        user = get_directory_user(conn, user_id)
        if user is None:
            raise KeyError(f"Directory user not found: {user_id}")
        resolved_user_ids.append(str(user["id"]))
    conn.execute("DELETE FROM directory_group_members WHERE group_id = ?", (group["id"],))
    conn.executemany(
        "INSERT OR IGNORE INTO directory_group_members(group_id, user_id) VALUES (?, ?)",
        [(group["id"], user_id) for user_id in resolved_user_ids],
    )
    if audit:
        insert_audit(
            conn,
            "directory_group_members_replace",
            actor_role,
            actor=actor,
            object_type="directory_group",
            object_id=group["id"],
            details={"member_count": len(resolved_user_ids), "members": resolved_user_ids},
        )
    return list_directory_group_members(conn, group["id"])


def list_directory_group_members(conn: sqlite3.Connection, group_id: str) -> list[dict[str, Any]]:
    ensure_directory_schema(conn)
    group = get_directory_group(conn, group_id)
    if group is None:
        raise KeyError(f"Directory group not found: {group_id}")
    rows = conn.execute(
        """
        SELECT u.*
        FROM directory_group_members gm
        JOIN directory_users u ON u.id = gm.user_id
        WHERE gm.group_id = ?
        ORDER BY u.user_name
        """,
        (group["id"],),
    ).fetchall()
    return rows_to_dicts(rows)


def list_directory_user_groups(conn: sqlite3.Connection, user_id: str) -> list[dict[str, Any]]:
    ensure_directory_schema(conn)
    user = get_directory_user(conn, user_id)
    if user is None:
        return []
    rows = conn.execute(
        """
        SELECT g.*
        FROM directory_group_members gm
        JOIN directory_groups g ON g.id = gm.group_id
        WHERE gm.user_id = ?
        ORDER BY g.display_name
        """,
        (user["id"],),
    ).fetchall()
    return rows_to_dicts(rows)


def delete_directory_group(
    conn: sqlite3.Connection,
    group_id: str,
    *,
    actor: str = "directory-sync",
    actor_role: str = "admin",
    audit: bool = True,
) -> dict[str, Any]:
    ensure_directory_schema(conn)
    group = get_directory_group(conn, group_id)
    if group is None:
        raise KeyError(f"Directory group not found: {group_id}")
    conn.execute("DELETE FROM directory_groups WHERE id = ?", (group["id"],))
    if audit:
        insert_audit(
            conn,
            "directory_group_delete",
            actor_role,
            actor=actor,
            object_type="directory_group",
            object_id=group["id"],
            details={"display_name": group.get("display_name")},
        )
    return group


def create_export_approval(
    conn: sqlite3.Connection,
    *,
    requester: str,
    requester_role: str,
    action: str,
    export_format: str,
    object_type: str,
    object_id: str | None,
    payload_hash: str,
    max_confidentiality: str,
    classifications: list[str],
    reason: str,
    justification: str,
    expires_at: str | None = None,
) -> dict[str, Any]:
    ensure_export_approval_schema(conn)
    cursor = conn.execute(
        """
        INSERT INTO export_approvals(
            requester, requester_role, action, export_format, object_type, object_id,
            payload_hash, max_confidentiality, classifications_json, reason,
            justification, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            requester,
            requester_role,
            action,
            export_format,
            object_type,
            object_id,
            payload_hash,
            max_confidentiality,
            json.dumps(classifications, ensure_ascii=False),
            encrypt_field(reason),
            encrypt_field(justification),
            expires_at,
        ),
    )
    approval_id = int(cursor.lastrowid)
    insert_audit(
        conn,
        "export_approval_request",
        requester_role,
        actor=requester,
        object_type=object_type,
        object_id=object_id,
        details={
            "approval_id": approval_id,
            "action": action,
            "format": export_format,
            "max_confidentiality": max_confidentiality,
            "classifications": classifications,
            "reason": reason,
        },
    )
    return get_export_approval(conn, approval_id)


def get_export_approval(conn: sqlite3.Connection, approval_id: int) -> dict[str, Any]:
    ensure_export_approval_schema(conn)
    row = conn.execute("SELECT * FROM export_approvals WHERE id = ?", (approval_id,)).fetchone()
    if row is None:
        raise KeyError(f"Export approval not found: {approval_id}")
    return row_to_dict(row) or {}


def list_export_approvals(conn: sqlite3.Connection, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    ensure_export_approval_schema(conn)
    capped_limit = max(1, min(int(limit), 500))
    if status:
        rows = conn.execute(
            "SELECT * FROM export_approvals WHERE status = ? ORDER BY id DESC LIMIT ?",
            (status, capped_limit),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM export_approvals ORDER BY id DESC LIMIT ?", (capped_limit,)).fetchall()
    return rows_to_dicts(rows)


def review_export_approval(
    conn: sqlite3.Connection,
    approval_id: int,
    *,
    approved: bool,
    reviewer: str,
    reviewer_role: str,
    comment: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    approval = get_export_approval(conn, approval_id)
    if approval.get("status") != "pending":
        raise ValueError(f"Export approval {approval_id} is not pending")
    status = "approved" if approved else "rejected"
    conn.execute(
        """
        UPDATE export_approvals
        SET status = ?,
            reviewed_by = ?,
            reviewer_role = ?,
            reviewed_at = CURRENT_TIMESTAMP,
            review_comment = ?,
            expires_at = COALESCE(?, expires_at)
        WHERE id = ?
        """,
        (status, reviewer, reviewer_role, encrypt_field(comment), expires_at, approval_id),
    )
    insert_audit(
        conn,
        "export_approval_approve" if approved else "export_approval_reject",
        reviewer_role,
        actor=reviewer,
        object_type=approval.get("object_type"),
        object_id=approval.get("object_id"),
        details={
            "approval_id": approval_id,
            "status": status,
            "format": approval.get("export_format"),
            "max_confidentiality": approval.get("max_confidentiality"),
            "comment": comment,
        },
    )
    return get_export_approval(conn, approval_id)


def consume_export_approval(
    conn: sqlite3.Connection,
    approval_id: int,
    *,
    requester_role: str,
    action: str,
    export_format: str,
    object_type: str,
    object_id: str | None,
    payload_hash: str,
    max_confidentiality: str,
    actor: str = "demo-user",
) -> dict[str, Any]:
    approval = get_export_approval(conn, approval_id)
    if approval.get("status") != "approved" or approval.get("consumed_at"):
        raise ValueError(f"Export approval {approval_id} is not available")
    expires_at = approval.get("expires_at")
    if expires_at:
        row = conn.execute("SELECT CASE WHEN ? < CURRENT_TIMESTAMP THEN 1 ELSE 0 END", (expires_at,)).fetchone()
        if row and int(row[0]) == 1:
            conn.execute("UPDATE export_approvals SET status = 'expired' WHERE id = ?", (approval_id,))
            raise ValueError(f"Export approval {approval_id} is expired")
    expected = {
        "action": action,
        "export_format": export_format,
        "object_type": object_type,
        "object_id": object_id,
        "payload_hash": payload_hash,
        "max_confidentiality": max_confidentiality,
    }
    for key, expected_value in expected.items():
        actual_value = approval.get(key)
        if (actual_value or None) != (expected_value or None):
            raise ValueError(f"Export approval {approval_id} does not match {key}")
    conn.execute(
        """
        UPDATE export_approvals
        SET status = 'used', consumed_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (approval_id,),
    )
    insert_audit(
        conn,
        "export_approval_consume",
        requester_role,
        actor=actor,
        object_type=object_type,
        object_id=object_id,
        details={
            "approval_id": approval_id,
            "action": action,
            "format": export_format,
            "max_confidentiality": max_confidentiality,
        },
    )
    return get_export_approval(conn, approval_id)


def ensure_ingest_manifest_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS ingest_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL UNIQUE,
            suffix TEXT,
            size_bytes INTEGER,
            checksum TEXT,
            status TEXT NOT NULL,
            source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
            error TEXT,
            result_json TEXT DEFAULT '{}',
            queued_at TEXT DEFAULT CURRENT_TIMESTAMP,
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_ingest_files_status ON ingest_files(status);
        CREATE INDEX IF NOT EXISTS idx_ingest_files_suffix ON ingest_files(suffix);
        """
    )


def upsert_ingest_file(
    conn: sqlite3.Connection,
    path: str,
    suffix: str,
    size_bytes: int | None,
    status: str,
    checksum: str | None = None,
    source_id: int | None = None,
    error: str | None = None,
    result: dict[str, Any] | None = None,
    mark_started: bool = False,
    mark_finished: bool = False,
) -> None:
    ensure_ingest_manifest_schema(conn)
    started_expr = "CURRENT_TIMESTAMP" if mark_started else "COALESCE(started_at, NULL)"
    finished_expr = "CURRENT_TIMESTAMP" if mark_finished else "COALESCE(finished_at, NULL)"
    conn.execute(
        f"""
        INSERT INTO ingest_files(path, suffix, size_bytes, checksum, status, source_id, error, result_json,
                                 started_at, finished_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, {"CURRENT_TIMESTAMP" if mark_started else "NULL"},
                {"CURRENT_TIMESTAMP" if mark_finished else "NULL"}, CURRENT_TIMESTAMP)
        ON CONFLICT(path) DO UPDATE SET
            suffix = excluded.suffix,
            size_bytes = excluded.size_bytes,
            checksum = COALESCE(excluded.checksum, ingest_files.checksum),
            status = excluded.status,
            source_id = COALESCE(excluded.source_id, ingest_files.source_id),
            error = excluded.error,
            result_json = excluded.result_json,
            started_at = {started_expr},
            finished_at = {finished_expr},
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            path,
            suffix,
            size_bytes,
            checksum,
            status,
            source_id,
            error,
            json.dumps(result or {}, ensure_ascii=False),
        ),
    )


def upsert_entity(conn: sqlite3.Connection, type_: str, name: str, normalized_name: str | None = None, aliases: list[str] | None = None) -> int:
    norm = (normalized_name or name).strip().lower()
    aliases_json = json.dumps(aliases or [], ensure_ascii=False)
    conn.execute(
        """
        INSERT OR IGNORE INTO entities(type, name, normalized_name, aliases_json)
        VALUES (?, ?, ?, ?)
        """,
        (type_, name, norm, aliases_json),
    )
    row = conn.execute(
        "SELECT id FROM entities WHERE type = ? AND normalized_name = ?",
        (type_, norm),
    ).fetchone()
    return int(row["id"])


def insert_source(conn: sqlite3.Connection, metadata: dict[str, Any], path: str | None = None, abstract: str | None = None) -> int:
    cur = conn.execute(
        """
        INSERT INTO sources(title, source_type, language, geography, additional_geography, year, date,
                            reliability_score, confidentiality, path, abstract, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            metadata.get("title") or Path(path or "untitled").stem,
            metadata.get("source_type") or "document",
            metadata.get("language"),
            metadata.get("geography"),
            metadata.get("additional_geography"),
            metadata.get("year"),
            metadata.get("date"),
            float(metadata.get("reliability_score", 0.5)),
            metadata.get("confidentiality", "internal"),
            encrypt_field(path),
            encrypt_field(abstract),
            json.dumps(metadata, ensure_ascii=False),
        ),
    )
    return int(cur.lastrowid)


def insert_document_chunk(
    conn: sqlite3.Connection,
    source_id: int,
    chunk_no: int,
    text: str,
    locator_type: str | None = None,
    locator: str | None = None,
    start_char: int | None = None,
    end_char: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> int:
    ensure_operational_schema(conn)
    locator_type, locator, metadata = _normalize_document_locator(chunk_no, locator_type, locator, metadata)
    cur = conn.execute(
        """
        INSERT INTO documents(source_id, chunk_no, text, locator_type, locator, start_char, end_char, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (source_id, chunk_no, text, locator_type, locator, start_char, end_char, json.dumps(metadata or {}, ensure_ascii=False)),
    )
    doc_id = int(cur.lastrowid)
    conn.execute(
        "INSERT INTO documents_fts(text, source_id, doc_id) VALUES (?, ?, ?)",
        (text, source_id, doc_id),
    )
    insert_document_embedding(conn, doc_id, source_id, text)
    return doc_id


def insert_document_embedding(
    conn: sqlite3.Connection,
    document_id: int,
    source_id: int,
    text: str,
    model: str = EMBEDDING_MODEL,
    dims: int = EMBEDDING_DIMS,
) -> None:
    vector_blob = vector_to_blob(embed_text(text, dims=dims))
    conn.execute(
        """
        INSERT OR REPLACE INTO document_embeddings(document_id, source_id, model, dims, vector_blob)
        VALUES (?, ?, ?, ?, ?)
        """,
        (document_id, source_id, model, dims, vector_blob),
    )


def insert_document_table(
    conn: sqlite3.Connection,
    source_id: int,
    document_id: int | None,
    locator: str | None,
    headers: list[str],
    rows: list[dict[str, Any]],
    table_type: str = "detected",
    confidence: float = 0.5,
) -> int:
    ensure_operational_schema(conn)
    if locator is None and document_id is not None:
        row = conn.execute("SELECT locator FROM documents WHERE id = ?", (document_id,)).fetchone()
        if row is not None:
            locator = row["locator"]
    cur = conn.execute(
        """
        INSERT INTO document_tables(source_id, document_id, locator, table_type, headers_json, rows_json, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            document_id,
            locator,
            table_type,
            json.dumps(headers, ensure_ascii=False),
            json.dumps(rows, ensure_ascii=False),
            confidence,
        ),
    )
    return int(cur.lastrowid)


def insert_fact(
    conn: sqlite3.Connection,
    source_id: int | None,
    subject_id: int | None,
    predicate: str,
    object_id: int | None = None,
    property_: str | None = None,
    comparator: str | None = None,
    numeric_value: float | None = None,
    min_value: float | None = None,
    max_value: float | None = None,
    unit: str | None = None,
    value_text: str | None = None,
    confidence: float = 0.5,
    extraction_confidence: float | None = None,
    validation_status: str = "valid",
    validation_warnings: list[str] | None = None,
    status: str = "candidate",
    document_id: int | None = None,
    evidence: str | None = None,
    evidence_locator: str | None = None,
    evidence_start: int | None = None,
    evidence_end: int | None = None,
    extractor_version: str = "dictionary-regex-v1",
    asserted_by: str = "auto-extractor",
) -> int:
    ensure_operational_schema(conn)
    if document_id is not None:
        row = conn.execute(
            "SELECT locator, text, start_char, end_char FROM documents WHERE id = ?",
            (document_id,),
        ).fetchone()
        if row is not None:
            if evidence_locator is None:
                evidence_locator = row["locator"]
            if evidence and (evidence_start is None or evidence_end is None):
                document_text = row["text"] or ""
                document_start = int(row["start_char"] or 0)
                match_start = document_text.find(evidence)
                if match_start >= 0:
                    evidence_start = document_start + match_start
                    evidence_end = evidence_start + len(evidence)
                else:
                    fallback_start = document_start
                    fallback_end = int(row["end_char"] or (fallback_start + max(len(document_text), len(evidence))))
                    evidence_start = fallback_start if evidence_start is None else evidence_start
                    evidence_end = max(evidence_start + 1, fallback_end) if evidence_end is None else evidence_end
    cur = conn.execute(
        """
        INSERT INTO facts(source_id, subject_id, predicate, object_id, property, comparator, numeric_value,
                          min_value, max_value, unit, value_text, confidence, extraction_confidence,
                          validation_status, validation_warnings_json, status, document_id, evidence,
                          evidence_locator, evidence_start, evidence_end, extractor_version, asserted_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            subject_id,
            predicate,
            object_id,
            property_,
            comparator,
            numeric_value,
            min_value,
            max_value,
            unit,
            value_text,
            confidence,
            extraction_confidence if extraction_confidence is not None else confidence,
            validation_status,
            json.dumps(validation_warnings or [], ensure_ascii=False),
            status,
            document_id,
            evidence,
            evidence_locator,
            evidence_start,
            evidence_end,
            extractor_version,
            asserted_by,
        ),
    )
    return int(cur.lastrowid)


def review_fact(conn: sqlite3.Connection, fact_id: int, reviewer: str, role: str, action: str, comment: str | None = None) -> dict[str, Any]:
    status_by_action = {
        "verify": "verified",
        "reject": "rejected",
        "comment": None,
        "mark_contradicted": "contradicted",
        "mark_superseded": "superseded",
    }
    if action not in status_by_action:
        raise ValueError(f"Unsupported fact review action: {action}")
    row = conn.execute("SELECT * FROM facts WHERE id = ?", (fact_id,)).fetchone()
    if row is None:
        raise KeyError(f"Fact not found: {fact_id}")
    next_status = status_by_action[action]
    conn.execute(
        """
        INSERT INTO fact_reviews(fact_id, reviewer, role, action, comment)
        VALUES (?, ?, ?, ?, ?)
        """,
        (fact_id, reviewer, role, action, comment),
    )
    if next_status:
        conn.execute(
            """
            UPDATE facts
            SET status = ?,
                verified_by = CASE WHEN ? = 'verified' THEN ? ELSE verified_by END,
                verified_at = CASE WHEN ? = 'verified' THEN CURRENT_TIMESTAMP ELSE verified_at END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (next_status, next_status, reviewer, next_status, fact_id),
        )
        conn.execute(
            """
            UPDATE fact_assignments
            SET status = 'completed',
                released_at = CURRENT_TIMESTAMP
            WHERE fact_id = ? AND status = 'active'
            """,
            (fact_id,),
        )
    updated = conn.execute("SELECT * FROM facts WHERE id = ?", (fact_id,)).fetchone()
    return row_to_dict(updated) or {}


def review_facts_bulk(
    conn: sqlite3.Connection,
    fact_ids: list[int],
    reviewer: str,
    role: str,
    action: str,
    comment: str | None = None,
) -> list[dict[str, Any]]:
    unique_ids = list(dict.fromkeys(int(fact_id) for fact_id in fact_ids))
    if not unique_ids:
        raise ValueError("fact_ids must not be empty")
    return [
        review_fact(conn, fact_id, reviewer=reviewer, role=role, action=action, comment=comment)
        for fact_id in unique_ids
    ]


def assign_facts(
    conn: sqlite3.Connection,
    fact_ids: list[int],
    assignee: str,
    assigned_by: str,
    role: str,
    due_at: str | None = None,
    comment: str | None = None,
) -> list[dict[str, Any]]:
    assignee = assignee.strip()
    if not assignee:
        raise ValueError("assignee must not be empty")
    unique_ids = list(dict.fromkeys(int(fact_id) for fact_id in fact_ids))
    if not unique_ids:
        raise ValueError("fact_ids must not be empty")
    assignments: list[dict[str, Any]] = []
    for fact_id in unique_ids:
        row = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone()
        if row is None:
            raise KeyError(f"Fact not found: {fact_id}")
        conn.execute(
            """
            UPDATE fact_assignments
            SET status = 'released',
                released_at = CURRENT_TIMESTAMP
            WHERE fact_id = ? AND status = 'active'
            """,
            (fact_id,),
        )
        cur = conn.execute(
            """
            INSERT INTO fact_assignments(fact_id, assignee, assigned_by, role, due_at, comment)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (fact_id, assignee, assigned_by, role, due_at, comment),
        )
        assignments.append(row_to_dict(conn.execute("SELECT * FROM fact_assignments WHERE id = ?", (cur.lastrowid,)).fetchone()) or {})
    insert_audit(
        conn,
        "fact_assignment_assign",
        role,
        actor=assigned_by,
        object_type="facts",
        object_id=",".join(str(fact_id) for fact_id in unique_ids),
        details={"assignee": assignee, "due_at": due_at, "comment": comment},
    )
    return assignments


def release_fact_assignments(
    conn: sqlite3.Connection,
    fact_ids: list[int],
    reviewer: str,
    role: str,
    comment: str | None = None,
) -> list[dict[str, Any]]:
    unique_ids = list(dict.fromkeys(int(fact_id) for fact_id in fact_ids))
    if not unique_ids:
        raise ValueError("fact_ids must not be empty")
    released: list[dict[str, Any]] = []
    for fact_id in unique_ids:
        row = conn.execute(
            "SELECT * FROM fact_assignments WHERE fact_id = ? AND status = 'active'",
            (fact_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Active assignment not found for fact: {fact_id}")
        conn.execute(
            """
            UPDATE fact_assignments
            SET status = 'released',
                released_at = CURRENT_TIMESTAMP,
                comment = COALESCE(?, comment)
            WHERE id = ?
            """,
            (comment, row["id"]),
        )
        released.append(row_to_dict(conn.execute("SELECT * FROM fact_assignments WHERE id = ?", (row["id"],)).fetchone()) or {})
    insert_audit(
        conn,
        "fact_assignment_release",
        role,
        actor=reviewer,
        object_type="facts",
        object_id=",".join(str(fact_id) for fact_id in unique_ids),
        details={"comment": comment},
    )
    return released


DISPUTE_SEVERITIES = {"low", "medium", "high", "critical"}
DISPUTE_STATUSES = {"open", "escalated", "resolved"}


def _dispute_row_with_sla(conn: sqlite3.Connection, dispute_id: int) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT fd.*, f.status AS fact_status, f.property, f.predicate, s.title AS source_title,
               CASE
                   WHEN fd.status IN ('resolved') THEN 'closed'
                   WHEN fd.due_at IS NOT NULL AND fd.due_at < CURRENT_TIMESTAMP THEN 'overdue'
                   WHEN fd.due_at IS NOT NULL THEN 'within_sla'
                   ELSE 'unassigned_sla'
               END AS sla_state,
               (SELECT COUNT(*) FROM fact_dispute_comments fdc WHERE fdc.dispute_id = fd.id) AS comments_count
        FROM fact_disputes fd
        JOIN facts f ON f.id = fd.fact_id
        LEFT JOIN sources s ON s.id = f.source_id
        WHERE fd.id = ?
        """,
        (dispute_id,),
    ).fetchone()
    return row_to_dict(row) or {}


def list_fact_disputes(
    conn: sqlite3.Connection,
    status: str | None = None,
    assignee: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    filters: list[str] = []
    values: list[Any] = []
    if status:
        filters.append("fd.status = ?")
        values.append(status)
    else:
        filters.append("fd.status IN ('open', 'escalated')")
    if assignee:
        filters.append("fd.assignee = ?")
        values.append(assignee)
    where = "WHERE " + " AND ".join(filters) if filters else ""
    rows = conn.execute(
        f"""
        SELECT fd.*, f.status AS fact_status, f.property, f.predicate, s.title AS source_title,
               CASE
                   WHEN fd.status IN ('resolved') THEN 'closed'
                   WHEN fd.due_at IS NOT NULL AND fd.due_at < CURRENT_TIMESTAMP THEN 'overdue'
                   WHEN fd.due_at IS NOT NULL THEN 'within_sla'
                   ELSE 'unassigned_sla'
               END AS sla_state,
               (SELECT COUNT(*) FROM fact_dispute_comments fdc WHERE fdc.dispute_id = fd.id) AS comments_count
        FROM fact_disputes fd
        JOIN facts f ON f.id = fd.fact_id
        LEFT JOIN sources s ON s.id = f.source_id
        {where}
        ORDER BY
            CASE fd.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,
            CASE WHEN fd.due_at IS NULL THEN 1 ELSE 0 END ASC,
            fd.due_at ASC,
            fd.id DESC
        LIMIT ?
        """,
        values + [limit],
    ).fetchall()
    return rows_to_dicts(rows)


def open_fact_dispute(
    conn: sqlite3.Connection,
    fact_id: int,
    opened_by: str,
    role: str,
    reason: str,
    severity: str = "medium",
    assignee: str | None = None,
    due_at: str | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    reason = reason.strip()
    if not reason:
        raise ValueError("reason must not be empty")
    if severity not in DISPUTE_SEVERITIES:
        raise ValueError(f"Unsupported dispute severity: {severity}")
    fact = conn.execute("SELECT * FROM facts WHERE id = ?", (fact_id,)).fetchone()
    if fact is None:
        raise KeyError(f"Fact not found: {fact_id}")
    cur = conn.execute(
        """
        INSERT INTO fact_disputes(fact_id, opened_by, role, severity, status, reason, assignee, due_at)
        VALUES (?, ?, ?, ?, 'open', ?, ?, ?)
        """,
        (fact_id, opened_by, role, severity, reason, assignee, due_at),
    )
    dispute_id = int(cur.lastrowid)
    if comment:
        add_fact_dispute_comment(conn, dispute_id, author=opened_by, role=role, comment=comment, audit=False)
    conn.execute(
        """
        UPDATE facts
        SET status = 'contradicted',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (fact_id,),
    )
    conn.execute(
        """
        INSERT INTO fact_reviews(fact_id, reviewer, role, action, comment)
        VALUES (?, ?, ?, 'open_dispute', ?)
        """,
        (fact_id, opened_by, role, reason),
    )
    insert_audit(
        conn,
        "fact_dispute_open",
        role,
        actor=opened_by,
        object_type="fact",
        object_id=str(fact_id),
        details={"dispute_id": dispute_id, "severity": severity, "assignee": assignee, "due_at": due_at, "reason": reason},
    )
    return _dispute_row_with_sla(conn, dispute_id)


def add_fact_dispute_comment(
    conn: sqlite3.Connection,
    dispute_id: int,
    author: str,
    role: str,
    comment: str,
    audit: bool = True,
) -> dict[str, Any]:
    comment = comment.strip()
    if not comment:
        raise ValueError("comment must not be empty")
    dispute = conn.execute("SELECT * FROM fact_disputes WHERE id = ?", (dispute_id,)).fetchone()
    if dispute is None:
        raise KeyError(f"Dispute not found: {dispute_id}")
    cur = conn.execute(
        """
        INSERT INTO fact_dispute_comments(dispute_id, author, role, comment)
        VALUES (?, ?, ?, ?)
        """,
        (dispute_id, author, role, comment),
    )
    conn.execute("UPDATE fact_disputes SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (dispute_id,))
    if audit:
        insert_audit(
            conn,
            "fact_dispute_comment",
            role,
            actor=author,
            object_type="dispute",
            object_id=str(dispute_id),
            details={"comment": comment},
        )
    return row_to_dict(conn.execute("SELECT * FROM fact_dispute_comments WHERE id = ?", (cur.lastrowid,)).fetchone()) or {}


def escalate_fact_dispute(
    conn: sqlite3.Connection,
    dispute_id: int,
    reviewer: str,
    role: str,
    assignee: str | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    dispute = conn.execute("SELECT * FROM fact_disputes WHERE id = ?", (dispute_id,)).fetchone()
    if dispute is None:
        raise KeyError(f"Dispute not found: {dispute_id}")
    if dispute["status"] == "resolved":
        raise ValueError("resolved dispute cannot be escalated")
    conn.execute(
        """
        UPDATE fact_disputes
        SET status = 'escalated',
            assignee = COALESCE(?, assignee),
            escalated_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (assignee, dispute_id),
    )
    if comment:
        add_fact_dispute_comment(conn, dispute_id, author=reviewer, role=role, comment=comment, audit=False)
    insert_audit(
        conn,
        "fact_dispute_escalate",
        role,
        actor=reviewer,
        object_type="dispute",
        object_id=str(dispute_id),
        details={"assignee": assignee, "comment": comment},
    )
    return _dispute_row_with_sla(conn, dispute_id)


def resolve_fact_dispute(
    conn: sqlite3.Connection,
    dispute_id: int,
    reviewer: str,
    role: str,
    resolution: str,
    fact_status: str | None = None,
) -> dict[str, Any]:
    resolution = resolution.strip()
    if not resolution:
        raise ValueError("resolution must not be empty")
    if fact_status and fact_status not in {"candidate", "verified", "rejected", "contradicted", "superseded"}:
        raise ValueError(f"Unsupported fact status: {fact_status}")
    dispute = conn.execute("SELECT * FROM fact_disputes WHERE id = ?", (dispute_id,)).fetchone()
    if dispute is None:
        raise KeyError(f"Dispute not found: {dispute_id}")
    conn.execute(
        """
        UPDATE fact_disputes
        SET status = 'resolved',
            resolved_by = ?,
            resolved_at = CURRENT_TIMESTAMP,
            resolution = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (reviewer, resolution, dispute_id),
    )
    if fact_status:
        conn.execute(
            """
            UPDATE facts
            SET status = ?,
                verified_by = CASE WHEN ? = 'verified' THEN ? ELSE verified_by END,
                verified_at = CASE WHEN ? = 'verified' THEN CURRENT_TIMESTAMP ELSE verified_at END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (fact_status, fact_status, reviewer, fact_status, int(dispute["fact_id"])),
        )
    conn.execute(
        """
        INSERT INTO fact_reviews(fact_id, reviewer, role, action, comment)
        VALUES (?, ?, ?, 'resolve_dispute', ?)
        """,
        (int(dispute["fact_id"]), reviewer, role, resolution),
    )
    insert_audit(
        conn,
        "fact_dispute_resolve",
        role,
        actor=reviewer,
        object_type="dispute",
        object_id=str(dispute_id),
        details={"resolution": resolution, "fact_status": fact_status},
    )
    return _dispute_row_with_sla(conn, dispute_id)


def fact_history(conn: sqlite3.Connection, fact_id: int) -> dict[str, Any]:
    fact = row_to_dict(conn.execute("SELECT * FROM facts WHERE id = ?", (fact_id,)).fetchone())
    if fact is None:
        raise KeyError(f"Fact not found: {fact_id}")
    reviews = rows_to_dicts(
        conn.execute(
            "SELECT * FROM fact_reviews WHERE fact_id = ? ORDER BY id DESC",
            (fact_id,),
        ).fetchall()
    )
    assignments = rows_to_dicts(
        conn.execute(
            "SELECT * FROM fact_assignments WHERE fact_id = ? ORDER BY id DESC",
            (fact_id,),
        ).fetchall()
    )
    supersedes = None
    if fact.get("supersedes_fact_id"):
        supersedes = row_to_dict(conn.execute("SELECT * FROM facts WHERE id = ?", (fact["supersedes_fact_id"],)).fetchone())
    superseded_by = rows_to_dicts(
        conn.execute(
            "SELECT * FROM facts WHERE supersedes_fact_id = ? ORDER BY id DESC",
            (fact_id,),
        ).fetchall()
    )
    disputes = rows_to_dicts(
        conn.execute(
            """
            SELECT fd.*,
                   CASE
                       WHEN fd.status IN ('resolved') THEN 'closed'
                       WHEN fd.due_at IS NOT NULL AND fd.due_at < CURRENT_TIMESTAMP THEN 'overdue'
                       WHEN fd.due_at IS NOT NULL THEN 'within_sla'
                       ELSE 'unassigned_sla'
                   END AS sla_state
            FROM fact_disputes fd
            WHERE fd.fact_id = ?
            ORDER BY fd.id DESC
            """,
            (fact_id,),
        ).fetchall()
    )
    for dispute in disputes:
        dispute["comments"] = rows_to_dicts(
            conn.execute(
                "SELECT * FROM fact_dispute_comments WHERE dispute_id = ? ORDER BY id ASC",
                (dispute["id"],),
            ).fetchall()
        )
    return {
        "fact": fact,
        "reviews": reviews,
        "assignments": assignments,
        "disputes": disputes,
        "supersedes": supersedes,
        "superseded_by": superseded_by,
    }


def supersede_fact(
    conn: sqlite3.Connection,
    fact_id: int,
    replacement_fact_id: int,
    reviewer: str,
    role: str,
    comment: str | None = None,
) -> dict[str, Any]:
    if fact_id == replacement_fact_id:
        raise ValueError("fact_id and replacement_fact_id must differ")
    old_fact = conn.execute("SELECT * FROM facts WHERE id = ?", (fact_id,)).fetchone()
    replacement = conn.execute("SELECT * FROM facts WHERE id = ?", (replacement_fact_id,)).fetchone()
    if old_fact is None:
        raise KeyError(f"Fact not found: {fact_id}")
    if replacement is None:
        raise KeyError(f"Replacement fact not found: {replacement_fact_id}")
    next_version = int(old_fact["version"] or 1) + 1
    conn.execute(
        """
        UPDATE facts
        SET status = 'superseded',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (fact_id,),
    )
    conn.execute(
        """
        UPDATE facts
        SET supersedes_fact_id = ?,
            version = CASE WHEN version < ? THEN ? ELSE version END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (fact_id, next_version, next_version, replacement_fact_id),
    )
    conn.execute(
        """
        INSERT INTO fact_reviews(fact_id, reviewer, role, action, comment)
        VALUES (?, ?, ?, 'mark_superseded', ?)
        """,
        (fact_id, reviewer, role, comment),
    )
    conn.execute(
        """
        UPDATE fact_assignments
        SET status = 'completed',
            released_at = CURRENT_TIMESTAMP
        WHERE fact_id = ? AND status = 'active'
        """,
        (fact_id,),
    )
    insert_audit(
        conn,
        "fact_supersede",
        role,
        actor=reviewer,
        object_type="fact",
        object_id=str(fact_id),
        details={"replacement_fact_id": replacement_fact_id, "comment": comment},
    )
    return fact_history(conn, replacement_fact_id)


def merge_entities(
    conn: sqlite3.Connection,
    survivor_id: int,
    duplicate_id: int,
    reviewer: str,
    role: str,
    comment: str | None = None,
) -> dict[str, Any]:
    if survivor_id == duplicate_id:
        raise ValueError("survivor_id and duplicate_id must differ")
    survivor = conn.execute("SELECT * FROM entities WHERE id = ?", (survivor_id,)).fetchone()
    duplicate = conn.execute("SELECT * FROM entities WHERE id = ?", (duplicate_id,)).fetchone()
    if survivor is None:
        raise KeyError(f"Survivor entity not found: {survivor_id}")
    if duplicate is None:
        raise KeyError(f"Duplicate entity not found: {duplicate_id}")

    aliases = set(json.loads(survivor["aliases_json"] or "[]"))
    aliases.add(duplicate["name"])
    aliases.add(duplicate["normalized_name"])
    aliases.update(json.loads(duplicate["aliases_json"] or "[]"))
    conn.execute("UPDATE entities SET aliases_json = ? WHERE id = ?", (json.dumps(sorted(aliases), ensure_ascii=False), survivor_id))

    conn.execute("UPDATE facts SET subject_id = ? WHERE subject_id = ?", (survivor_id, duplicate_id))
    conn.execute("UPDATE facts SET object_id = ? WHERE object_id = ?", (survivor_id, duplicate_id))

    edge_rows = conn.execute(
        """
        SELECT * FROM graph_edges
        WHERE subject_id = ? OR object_id = ?
        """,
        (duplicate_id, duplicate_id),
    ).fetchall()
    for edge in edge_rows:
        conn.execute(
            """
            INSERT OR IGNORE INTO graph_edges(source_id, subject_id, predicate, object_id, confidence, evidence)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                edge["source_id"],
                survivor_id if edge["subject_id"] == duplicate_id else edge["subject_id"],
                edge["predicate"],
                survivor_id if edge["object_id"] == duplicate_id else edge["object_id"],
                edge["confidence"],
                edge["evidence"],
            ),
        )
    conn.execute("DELETE FROM graph_edges WHERE subject_id = ? OR object_id = ?", (duplicate_id, duplicate_id))
    conn.execute("DELETE FROM entities WHERE id = ?", (duplicate_id,))
    insert_audit(
        conn,
        "entity_merge",
        role,
        actor=reviewer,
        object_type="entity",
        object_id=str(survivor_id),
        details={"duplicate_id": duplicate_id, "comment": comment},
    )
    return row_to_dict(conn.execute("SELECT * FROM entities WHERE id = ?", (survivor_id,)).fetchone()) or {}


def split_entity(
    conn: sqlite3.Connection,
    source_entity_id: int,
    new_type: str,
    new_name: str,
    aliases: list[str] | None,
    reviewer: str,
    role: str,
    comment: str | None = None,
    move_fact_ids: list[int] | None = None,
    move_edge_ids: list[int] | None = None,
) -> dict[str, Any]:
    source = conn.execute("SELECT * FROM entities WHERE id = ?", (source_entity_id,)).fetchone()
    if source is None:
        raise KeyError(f"Source entity not found: {source_entity_id}")
    new_id = upsert_entity(conn, new_type, new_name, new_name, aliases or [])
    for fact_id in move_fact_ids or []:
        conn.execute("UPDATE facts SET subject_id = ? WHERE id = ? AND subject_id = ?", (new_id, fact_id, source_entity_id))
        conn.execute("UPDATE facts SET object_id = ? WHERE id = ? AND object_id = ?", (new_id, fact_id, source_entity_id))

    edge_rows = []
    if move_edge_ids:
        placeholders = ",".join("?" for _ in move_edge_ids)
        edge_rows = conn.execute(
            f"""
            SELECT * FROM graph_edges
            WHERE id IN ({placeholders}) AND (subject_id = ? OR object_id = ?)
            """,
            list(move_edge_ids) + [source_entity_id, source_entity_id],
        ).fetchall()
    for edge in edge_rows:
        conn.execute(
            """
            INSERT OR IGNORE INTO graph_edges(source_id, subject_id, predicate, object_id, confidence, evidence)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                edge["source_id"],
                new_id if edge["subject_id"] == source_entity_id else edge["subject_id"],
                edge["predicate"],
                new_id if edge["object_id"] == source_entity_id else edge["object_id"],
                edge["confidence"],
                edge["evidence"],
            ),
        )
        conn.execute("DELETE FROM graph_edges WHERE id = ?", (edge["id"],))
    insert_audit(
        conn,
        "entity_split",
        role,
        actor=reviewer,
        object_type="entity",
        object_id=str(source_entity_id),
        details={
            "new_entity_id": new_id,
            "new_type": new_type,
            "new_name": new_name,
            "move_fact_ids": move_fact_ids or [],
            "move_edge_ids": move_edge_ids or [],
            "comment": comment,
        },
    )
    return row_to_dict(conn.execute("SELECT * FROM entities WHERE id = ?", (new_id,)).fetchone()) or {}


def insert_edge(
    conn: sqlite3.Connection,
    source_id: int | None,
    subject_id: int,
    predicate: str,
    object_id: int,
    confidence: float = 0.5,
    evidence: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO graph_edges(source_id, subject_id, predicate, object_id, confidence, evidence)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (source_id, subject_id, predicate, object_id, confidence, evidence),
    )


def ensure_demo_db() -> Path:
    report = readiness_report(DB_PATH)
    if not report["ready"]:
        missing_dicts = [file for file, exists in report["dictionary_files"].items() if not exists]
        if missing_dicts:
            raise RuntimeError(f"Knowledge base dictionaries are missing: {', '.join(missing_dicts)}")
        from .seed_data import rebuild_demo_database
        rebuild_demo_database(DB_PATH)
        report = readiness_report(DB_PATH)
        if not report["ready"]:
            raise RuntimeError("Knowledge base is not ready after rebuild: " + "; ".join(report["issues"]))
    return DB_PATH
