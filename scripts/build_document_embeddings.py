from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import connect, ensure_operational_schema, insert_document_embedding
from app.embeddings import EMBEDDING_MODEL


def build_document_embeddings(limit: int | None = None, refresh: bool = False, commit_every: int = 1000) -> dict:
    processed = 0
    with connect() as conn:
        ensure_operational_schema(conn)
        where = ""
        if not refresh:
            where = """
            WHERE NOT EXISTS (
                SELECT 1 FROM document_embeddings de
                WHERE de.document_id = d.id AND de.model = ?
            )
            """
            params: list[object] = [EMBEDDING_MODEL]
        else:
            params = []
        limit_clause = "LIMIT ?" if limit else ""
        if limit:
            params.append(limit)
        rows = conn.execute(
            f"""
            SELECT d.id, d.source_id, d.text
            FROM documents d
            {where}
            ORDER BY d.id
            {limit_clause}
            """,
            params,
        ).fetchall()
        for row in rows:
            insert_document_embedding(conn, int(row["id"]), int(row["source_id"]), str(row["text"]))
            processed += 1
            if processed % commit_every == 0:
                conn.commit()
        total_documents = int(conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0])
        total_embeddings = int(conn.execute("SELECT COUNT(*) FROM document_embeddings WHERE model = ?", (EMBEDDING_MODEL,)).fetchone()[0])
    return {
        "model": EMBEDDING_MODEL,
        "processed": processed,
        "total_documents": total_documents,
        "total_embeddings": total_embeddings,
        "coverage": round(total_embeddings / total_documents, 6) if total_documents else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build deterministic local document embeddings for hybrid retrieval.")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--refresh", action="store_true", help="Rebuild embeddings even when a row already exists")
    parser.add_argument("--commit-every", type=int, default=1000)
    args = parser.parse_args()
    print(json.dumps(build_document_embeddings(limit=args.limit, refresh=args.refresh, commit_every=args.commit_every), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
