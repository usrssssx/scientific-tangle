from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import connect, default_chunk_locator, ensure_operational_schema, insert_document_table
from app.extract import EXTRACTOR_VERSION, extract_table_rows, normalize_text


LOCATOR_RE = re.compile(r"\[(page\s+\d+|slide\s+\d+:[^\]]+|sheet:[^\]]+|part:[^\]]+)\]")


def parse_locator(text: str) -> tuple[str | None, str | None, dict[str, Any]]:
    match = LOCATOR_RE.search(text[:300])
    if not match:
        return None, None, {}
    body = match.group(1).strip()
    if body.startswith("page "):
        page = body.split()[1]
        return "page", f"page {page}", {"page": int(page)}
    if body.startswith("slide "):
        slide = re.match(r"slide\s+(\d+):\s*(.+)", body)
        if slide:
            return "slide", f"slide {slide.group(1)}", {"slide": int(slide.group(1)), "part": slide.group(2)}
        return "slide", body, {}
    if body.startswith("sheet:"):
        sheet = body.removeprefix("sheet:").strip()
        parts = [part.strip() for part in sheet.split(";")]
        metadata = {"sheet": parts[0]} if parts else {}
        for part in parts[1:]:
            if ":" in part:
                key, value = part.split(":", 1)
                metadata[key.strip()] = value.strip()
        return "sheet", parts[0] if parts else sheet, metadata
    if body.startswith("part:"):
        part = body.removeprefix("part:").strip()
        return "part", part, {"part": part}
    return None, None, {}


def evidence_needle(evidence: str) -> str:
    clean = normalize_text(evidence)
    if len(clean) > 260:
        return clean[:260]
    return clean


def backfill(conn, table_limit: int = 2000) -> dict[str, int]:
    ensure_operational_schema(conn)
    stats = defaultdict(int)

    docs = conn.execute(
        """
        SELECT id, source_id, chunk_no, text, locator, locator_type, metadata_json
        FROM documents
        ORDER BY source_id, chunk_no
        """
    ).fetchall()
    docs_by_source: dict[int, list[dict[str, Any]]] = defaultdict(list)
    docs_by_id: dict[int, dict[str, Any]] = {}
    for doc in docs:
        item = dict(doc)
        item["normalized_text"] = normalize_text(item["text"] or "")
        locator_type, locator, metadata = parse_locator(item["text"] or "")
        if not locator:
            locator_type, locator, metadata = default_chunk_locator(int(item["chunk_no"]))
        if item.get("locator") is None and locator:
            try:
                stored_metadata = json.loads(item.get("metadata_json") or "{}")
            except json.JSONDecodeError:
                stored_metadata = {}
            stored_metadata.update({key: value for key, value in metadata.items() if key not in stored_metadata})
            conn.execute(
                """
                UPDATE documents
                SET locator_type = ?, locator = ?, start_char = COALESCE(start_char, 0),
                    end_char = COALESCE(end_char, length(text)), metadata_json = ?
                WHERE id = ?
                """,
                (locator_type, locator, json.dumps(stored_metadata, ensure_ascii=False), item["id"]),
            )
            item["locator_type"] = locator_type
            item["locator"] = locator
            stats["documents_locator_backfilled"] += 1
        docs_by_source[int(item["source_id"])].append(item)
        docs_by_id[int(item["id"])] = item

    facts = conn.execute(
        """
        SELECT id, source_id, evidence, document_id, evidence_locator, evidence_start, evidence_end
        FROM facts
        WHERE source_id IS NOT NULL AND evidence IS NOT NULL
        ORDER BY source_id, id
        """
    ).fetchall()
    for fact in facts:
        if fact["document_id"] is not None and fact["evidence_start"] is not None:
            if fact["evidence_locator"] is None:
                doc = docs_by_id.get(int(fact["document_id"]))
                if doc and doc.get("locator"):
                    conn.execute(
                        "UPDATE facts SET evidence_locator = ? WHERE id = ?",
                        (doc["locator"], fact["id"]),
                    )
                    stats["facts_locator_backfilled"] += 1
            continue
        needle = evidence_needle(fact["evidence"] or "")
        if not needle:
            continue
        candidates = docs_by_source.get(int(fact["source_id"]), [])
        best = None
        for doc in candidates:
            text = doc.get("normalized_text") or ""
            pos = text.find(needle)
            if pos >= 0:
                best = (doc, pos, pos + len(needle))
                break
            short = needle[:120]
            if len(short) >= 40:
                pos = text.find(short)
                if pos >= 0:
                    best = (doc, pos, pos + len(short))
                    break
        if best is None:
            stats["facts_unmatched"] += 1
            continue
        doc, start, end = best
        conn.execute(
            """
            UPDATE facts
            SET document_id = COALESCE(document_id, ?),
                evidence_locator = COALESCE(evidence_locator, ?),
                evidence_start = COALESCE(evidence_start, ?),
                evidence_end = COALESCE(evidence_end, ?),
                extractor_version = COALESCE(extractor_version, ?)
            WHERE id = ?
            """,
            (doc["id"], doc.get("locator"), start, end, EXTRACTOR_VERSION, fact["id"]),
        )
        stats["facts_evidence_backfilled"] += 1

    existing_table_docs = {
        int(row["document_id"])
        for row in conn.execute("SELECT DISTINCT document_id FROM document_tables WHERE document_id IS NOT NULL").fetchall()
    }
    for doc in docs:
        if stats["tables_backfilled"] >= table_limit:
            break
        if int(doc["id"]) in existing_table_docs:
            continue
        table = extract_table_rows(doc["text"] or "")
        if not table:
            continue
        headers, rows = table
        insert_document_table(
            conn,
            source_id=int(doc["source_id"]),
            document_id=int(doc["id"]),
            locator=doc.get("locator"),
            headers=headers,
            rows=rows,
            table_type="backfilled_pipe_table",
            confidence=0.45,
        )
        stats["tables_backfilled"] += 1
    return dict(stats)


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill document locators, fact evidence spans, and simple table artifacts.")
    parser.add_argument("--table-limit", type=int, default=2000)
    args = parser.parse_args()

    with connect() as conn:
        stats = backfill(conn, table_limit=args.table_limit)
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
