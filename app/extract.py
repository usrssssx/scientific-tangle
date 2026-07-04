from __future__ import annotations

import csv
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from .converters import convert_legacy_office, detect_conversion_capabilities, ocr_pdf_text
from .config import DICTIONARY_DIR

EXTRACTOR_VERSION = "dictionary-regex-v2"


@dataclass(frozen=True)
class EntityHit:
    type: str
    canonical: str
    alias: str
    start: int
    end: int


@dataclass(frozen=True)
class NumericHit:
    property: str | None
    comparator: str
    value: float | None
    min_value: float | None
    max_value: float | None
    unit: str
    evidence: str
    start: int
    end: int


@dataclass(frozen=True)
class TextChunk:
    text: str
    locator_type: str | None = None
    locator: str | None = None
    start_char: int | None = None
    end_char: int | None = None
    metadata: dict[str, Any] | None = None


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_domain_terms() -> dict[str, Any]:
    return load_json(DICTIONARY_DIR / "domain_terms.json")


def load_units() -> dict[str, list[str]]:
    return load_json(DICTIONARY_DIR / "units.json")


def normalize_text(text: str) -> str:
    text = text.replace("ё", "е").replace("Ё", "Е")
    text = re.sub(r"[\u00A0\t]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def normalize_key(text: str) -> str:
    return normalize_text(text).lower().strip()


def _safe_regex_alias(alias: str) -> str:
    escaped = re.escape(alias.strip())
    if re.search(r"^[\wа-яА-ЯёЁ]+$", alias, re.IGNORECASE):
        return rf"(?<![\wа-яА-ЯёЁ]){escaped}(?![\wа-яА-ЯёЁ])"
    return escaped


_ENTITY_MATCHER_CACHE: dict[int, list[tuple[str, re.Pattern[str], dict[str, list[tuple[str, str]]]]]] = {}


def _entity_matchers(terms: dict[str, Any]) -> list[tuple[str, re.Pattern[str], dict[str, list[tuple[str, str]]]]]:
    cache_key = id(terms)
    cached = _ENTITY_MATCHER_CACHE.get(cache_key)
    if cached is not None:
        return cached

    type_map = {
        "materials": "Material",
        "processes": "Process",
        "equipment": "Equipment",
        "properties": "Property",
        "geography": "Geography",
    }
    matchers: list[tuple[str, re.Pattern[str], dict[str, list[tuple[str, str]]]]] = []
    for category, entity_type in type_map.items():
        alias_entries: list[tuple[str, str, str]] = []
        alias_map: dict[str, list[tuple[str, str]]] = {}
        for canonical, aliases in terms.get(category, {}).items():
            for alias in aliases:
                alias_norm = normalize_text(alias)
                if not alias_norm:
                    continue
                alias_entries.append((alias_norm, canonical, alias))
                alias_map.setdefault(normalize_key(alias_norm), []).append((canonical, alias))
        if not alias_entries:
            continue
        alias_entries.sort(key=lambda item: len(item[0]), reverse=True)
        pattern = "|".join(f"(?:{_safe_regex_alias(alias_norm)})" for alias_norm, _, _ in alias_entries)
        matchers.append((entity_type, re.compile(pattern, flags=re.IGNORECASE), alias_map))

    _ENTITY_MATCHER_CACHE[cache_key] = matchers
    return matchers


def extract_entities(text: str, terms: dict[str, Any] | None = None) -> list[EntityHit]:
    terms = terms or load_domain_terms()
    normalized = normalize_text(text)
    hits: list[EntityHit] = []
    for entity_type, pattern, alias_map in _entity_matchers(terms):
        for match in pattern.finditer(normalized):
            for canonical, alias in alias_map.get(normalize_key(match.group(0)), []):
                hits.append(EntityHit(entity_type, canonical, alias, match.start(), match.end()))
    # de-duplicate exact canonical/type hits, keep earliest evidence
    dedup: dict[tuple[str, str], EntityHit] = {}
    for hit in sorted(hits, key=lambda h: (h.start, -(h.end - h.start))):
        key = (hit.type, hit.canonical)
        if key not in dedup:
            dedup[key] = hit
    return list(dedup.values())


def canonical_unit(unit: str, units: dict[str, list[str]] | None = None) -> str:
    units = units or load_units()
    u = unit.strip().lower().replace("³", "3")
    u = u.replace(" ", "")
    for canonical, aliases in units.items():
        for alias in aliases:
            a = alias.lower().replace("³", "3").replace(" ", "")
            if u == a:
                return canonical
    return u


def _to_float(value: str) -> float:
    return float(value.replace(",", "."))


def _normalize_comparator(raw: str | None, is_range: bool = False) -> str:
    if is_range:
        return "between"
    if raw is None:
        return "="
    cmp_ = raw.strip().lower()
    mapping = {
        "≤": "<=",
        "<=" : "<=",
        "не более": "<=",
        "до": "<=",
        "ниже": "<",
        "менее": "<",
        "<": "<",
        "≥": ">=",
        ">=": ">=",
        "не менее": ">=",
        "от": ">=",
        "выше": ">",
        "более": ">",
        ">": ">",
        "=": "=",
    }
    return mapping.get(cmp_, cmp_ or "=")


def _build_unit_pattern(units: dict[str, list[str]]) -> str:
    aliases: list[str] = []
    for values in units.values():
        aliases.extend(values)
    aliases = sorted(set(aliases), key=len, reverse=True)
    return "(?:" + "|".join(re.escape(a) for a in aliases) + ")"


def _infer_property(context: str, terms: dict[str, Any]) -> str | None:
    context_norm = normalize_key(context)
    best: tuple[int, int, str] | None = None
    for prop, aliases in terms.get("properties", {}).items():
        for alias in aliases:
            alias_norm = normalize_key(alias)
            for match in re.finditer(_safe_regex_alias(alias_norm), context_norm, flags=re.IGNORECASE):
                idx = match.start()
                alias_len = len(alias_norm)
                if best is None or idx > best[0] or (idx == best[0] and alias_len > best[1]):
                    best = (idx, alias_len, prop)
    if best and best[2] in {"capex", "opex", "cost", "temperature", "recovery", "flow_velocity", "tds"}:
        return best[2]
    # material concentrations are often written as Ca 200-300 mg/l, Mg 200-300 mg/l.
    for material_prop, aliases in {
        "calcium_concentration": ["ca", "кальций", "calcium"],
        "magnesium_concentration": ["mg", "магний", "magnesium"],
        "sodium_concentration": ["na", "натрий", "sodium"],
        "sulfate_concentration": ["сульфаты", "so4", "sulfates"],
        "chloride_concentration": ["хлориды", "cl", "chlorides"],
    }.items():
        for alias in aliases:
            if re.search(_safe_regex_alias(alias), context_norm, flags=re.IGNORECASE):
                idx = context_norm.rfind(alias)
                if best is None or idx > best[0]:
                    best = (idx, len(alias), material_prop)
    return best[2] if best else None


def extract_numeric_conditions(text: str, terms: dict[str, Any] | None = None, units: dict[str, list[str]] | None = None) -> list[NumericHit]:
    terms = terms or load_domain_terms()
    units = units or load_units()
    clean = normalize_text(text)
    unit_pattern = _build_unit_pattern(units)
    num = r"\d+(?:[\.,]\d+)?"
    cmp_pattern = r"(?:≤|>=|=>|<=|<|>|=|до|от|менее|более|ниже|выше|не\s+более|не\s+менее)"
    # Range first: 200-300 мг/л, 0.15–0.30 m/s
    range_re = re.compile(
        rf"(?P<min>{num})\s*(?:-|–|—|to|до)\s*(?P<max>{num})\s*(?P<unit>{unit_pattern})",
        flags=re.IGNORECASE,
    )
    # Single value with comparator: ≤1000 мг/дм³, flow velocity <0.10 m/s
    single_re = re.compile(
        rf"(?P<cmp>{cmp_pattern})?\s*(?P<value>{num})\s*(?P<unit>{unit_pattern})",
        flags=re.IGNORECASE,
    )

    hits: list[NumericHit] = []
    occupied: list[tuple[int, int]] = []
    for match in range_re.finditer(clean):
        start, end = match.span()
        context = clean[max(0, start - 110): end]
        prop = _infer_property(context, terms)
        hit = NumericHit(
            property=prop,
            comparator="between",
            value=None,
            min_value=_to_float(match.group("min")),
            max_value=_to_float(match.group("max")),
            unit=canonical_unit(match.group("unit"), units),
            evidence=context.strip(),
            start=start,
            end=end,
        )
        hits.append(hit)
        occupied.append((start, end))

    for match in single_re.finditer(clean):
        start, end = match.span()
        if any(not (end <= s or start >= e) for s, e in occupied):
            continue
        raw_cmp = match.group("cmp")
        # Drop bare values without comparator if the previous chars suggest a year/date false-positive.
        context = clean[max(0, start - 110): end]
        prop = _infer_property(context, terms)
        hit = NumericHit(
            property=prop,
            comparator=_normalize_comparator(raw_cmp),
            value=_to_float(match.group("value")),
            min_value=None,
            max_value=None,
            unit=canonical_unit(match.group("unit"), units),
            evidence=context.strip(),
            start=start,
            end=end,
        )
        hits.append(hit)
    return sorted(hits, key=lambda h: h.start)


def parse_front_matter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    meta_block = parts[1]
    body = parts[2].strip()
    meta: dict[str, Any] = {}
    for line in meta_block.splitlines():
        if not line.strip() or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value.lower() in {"true", "false"}:
            meta[key] = value.lower() == "true"
        else:
            try:
                if "." in value:
                    meta[key] = float(value)
                else:
                    meta[key] = int(value)
            except ValueError:
                meta[key] = value.strip('"').strip("'")
    return meta, body


def chunk_text(text: str, max_chars: int = 1800, overlap: int = 200) -> list[str]:
    text = normalize_text(text)
    if len(text) <= max_chars:
        return [text] if text else []
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + max_chars)
        if end < len(text):
            split_at = max(text.rfind(". ", start, end), text.rfind("\n", start, end))
            if split_at > start + max_chars // 2:
                end = split_at + 1
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(0, end - overlap)
    return chunks


_LOCATOR_RE = re.compile(r"^\[(page\s+\d+|slide\s+\d+:[^\]]+|sheet:[^\]]+|part:[^\]]+)\]\s*$", flags=re.MULTILINE)


def _parse_locator(marker: str) -> tuple[str | None, str | None, dict[str, Any]]:
    body = marker.strip()[1:-1].strip()
    if body.startswith("page "):
        page = body.split()[1]
        return "page", f"page {page}", {"page": int(page)}
    if body.startswith("slide "):
        slide_match = re.match(r"slide\s+(\d+):\s*(.+)", body)
        if slide_match:
            return "slide", f"slide {slide_match.group(1)}", {"slide": int(slide_match.group(1)), "part": slide_match.group(2)}
        return "slide", body, {}
    if body.startswith("sheet:"):
        sheet = body.removeprefix("sheet:").strip()
        metadata: dict[str, Any] = {}
        parts = [part.strip() for part in sheet.split(";")]
        if parts:
            metadata["sheet"] = parts[0]
        for part in parts[1:]:
            if ":" in part:
                key, value = part.split(":", 1)
                metadata[key.strip()] = value.strip()
        return "sheet", parts[0] if parts else sheet, metadata
    if body.startswith("part:"):
        part = body.removeprefix("part:").strip()
        return "part", part, {"part": part}
    return None, None, {}


def _chunk_positions(body: str, chunks: list[str]) -> list[tuple[int | None, int | None]]:
    normalized_body = normalize_text(body)
    positions: list[tuple[int | None, int | None]] = []
    cursor = 0
    for chunk in chunks:
        idx = normalized_body.find(chunk, cursor)
        if idx < 0:
            idx = normalized_body.find(chunk)
        if idx < 0:
            positions.append((None, None))
        else:
            positions.append((idx, idx + len(chunk)))
            cursor = max(idx + 1, idx + len(chunk) - 200)
    return positions


def _chunk_lines_preserving(body: str, max_chars: int = 1800) -> tuple[list[str], list[tuple[int | None, int | None]]]:
    chunks: list[str] = []
    positions: list[tuple[int | None, int | None]] = []
    current: list[str] = []
    current_start: int | None = None
    cursor = 0
    for line in body.splitlines(keepends=True):
        line_start = cursor
        cursor += len(line)
        if not line.strip():
            continue
        if current and sum(len(part) for part in current) + len(line) > max_chars:
            text = "".join(current).strip()
            if text:
                chunks.append(text)
                positions.append((current_start, (current_start or 0) + len("".join(current))))
            current = []
            current_start = None
        if current_start is None:
            current_start = line_start
        current.append(line)
    if current:
        text = "".join(current).strip()
        if text:
            chunks.append(text)
            positions.append((current_start, (current_start or 0) + len("".join(current))))
    return chunks, positions


def chunk_text_with_locations(text: str, max_chars: int = 1800, overlap: int = 200) -> list[TextChunk]:
    markers = list(_LOCATOR_RE.finditer(text))
    if not markers:
        chunks = chunk_text(text, max_chars=max_chars, overlap=overlap)
        positions = _chunk_positions(text, chunks)
        return [TextChunk(chunk, start_char=start, end_char=end, metadata={}) for chunk, (start, end) in zip(chunks, positions)]

    result: list[TextChunk] = []
    for idx, marker in enumerate(markers):
        next_start = markers[idx + 1].start() if idx + 1 < len(markers) else len(text)
        body = text[marker.end():next_start].strip()
        locator_type, locator, metadata = _parse_locator(marker.group(0))
        if locator_type == "sheet":
            chunks, positions = _chunk_lines_preserving(body, max_chars=max_chars)
        else:
            chunks = chunk_text(body, max_chars=max_chars, overlap=overlap)
            positions = _chunk_positions(body, chunks)
        if not chunks:
            continue
        for chunk, (start, end) in zip(chunks, positions):
            result.append(
                TextChunk(
                    text=chunk,
                    locator_type=locator_type,
                    locator=locator,
                    start_char=start,
                    end_char=end,
                    metadata=dict(metadata),
                )
            )
    return result


def validate_numeric_hit(hit: NumericHit) -> tuple[str, list[str]]:
    warnings: list[str] = []
    values = [v for v in [hit.value, hit.min_value, hit.max_value] if v is not None]
    if hit.min_value is not None and hit.max_value is not None and hit.min_value > hit.max_value:
        warnings.append("range_min_gt_max")
    if hit.unit != "celsius" and any(v < 0 for v in values):
        warnings.append("negative_value_for_non_temperature_unit")
    if hit.unit == "percent" and any(v < 0 or v > 100 for v in values):
        warnings.append("percent_outside_0_100")
    if hit.unit == "celsius" and any(v < -100 or v > 2000 for v in values):
        warnings.append("temperature_outside_expected_range")
    if hit.unit == "m_s" and any(v < 0 or v > 50 for v in values):
        warnings.append("velocity_outside_expected_range")
    if hit.unit == "mg_l" and any(v < 0 or v > 1_000_000 for v in values):
        warnings.append("concentration_outside_expected_range")
    if hit.unit in {"rub_m3", "usd_m3"} and any(v <= 0 for v in values):
        warnings.append("cost_not_positive")
    return ("suspicious" if warnings else "valid", warnings)


def extract_table_rows(text: str, max_rows: int = 50) -> tuple[list[str], list[dict[str, Any]]] | None:
    lines = [line.strip() for line in text.splitlines() if " | " in line and line.strip()]
    if len(lines) < 2:
        return None
    parsed = [[cell.strip() for cell in line.split("|")] for line in lines]
    width = max(len(row) for row in parsed)
    if width < 2:
        return None
    headers = parsed[0]
    if len(headers) != width or any(not h for h in headers):
        headers = [f"column_{idx + 1}" for idx in range(width)]
        data_rows = parsed
    else:
        data_rows = parsed[1:]
    rows: list[dict[str, Any]] = []
    for row in data_rows[:max_rows]:
        padded = row + [""] * (width - len(row))
        rows.append({headers[idx] if idx < len(headers) else f"column_{idx + 1}": padded[idx] for idx in range(width)})
    if not rows:
        return None
    return headers, rows


def _xml_text_nodes(xml_bytes: bytes) -> list[str]:
    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError:
        return []
    texts: list[str] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag in {"t", "instrText"} and element.text:
            texts.append(element.text)
    return texts


def _natural_key(value: str) -> list[int | str]:
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", value)]


def _read_docx_like_text(path: Path) -> str:
    parts = [
        "word/document.xml",
        "word/footnotes.xml",
        "word/endnotes.xml",
    ]
    with zipfile.ZipFile(path) as zf:
        parts.extend(name for name in zf.namelist() if re.match(r"word/(header|footer)\d+\.xml$", name))
        blocks = []
        for name in sorted(set(parts), key=_natural_key):
            if name not in zf.namelist():
                continue
            texts = _xml_text_nodes(zf.read(name))
            if texts:
                blocks.append(f"[part: {name}]\n" + " ".join(texts))
    return "\n".join(blocks)


def _read_pptx_text(path: Path) -> str:
    with zipfile.ZipFile(path) as zf:
        slides = sorted(
            [name for name in zf.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", name)],
            key=_natural_key,
        )
        blocks = []
        for idx, name in enumerate(slides, 1):
            texts = _xml_text_nodes(zf.read(name))
            if texts:
                blocks.append(f"[slide {idx}: {Path(name).name}]\n" + " ".join(texts))
    return "\n".join(blocks)


def _xlsx_shared_strings(zf: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in zf.namelist():
        return []
    try:
        root = ElementTree.fromstring(zf.read("xl/sharedStrings.xml"))
    except ElementTree.ParseError:
        return []
    values = []
    for si in root.iter():
        if si.tag.rsplit("}", 1)[-1] != "si":
            continue
        texts = []
        for node in si.iter():
            if node.tag.rsplit("}", 1)[-1] == "t" and node.text:
                texts.append(node.text)
        values.append("".join(texts))
    return values


def _xlsx_sheet_names(zf: zipfile.ZipFile) -> dict[str, str]:
    names: dict[str, str] = {}
    if "xl/workbook.xml" not in zf.namelist() or "xl/_rels/workbook.xml.rels" not in zf.namelist():
        return names
    try:
        workbook = ElementTree.fromstring(zf.read("xl/workbook.xml"))
        rels = ElementTree.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
    except ElementTree.ParseError:
        return names
    rel_targets: dict[str, str] = {}
    for rel in rels:
        rel_id = rel.attrib.get("Id")
        target = rel.attrib.get("Target")
        if rel_id and target:
            rel_targets[rel_id] = "xl/" + target.lstrip("/")
    for sheet in workbook.iter():
        if sheet.tag.rsplit("}", 1)[-1] != "sheet":
            continue
        rel_id = sheet.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
        name = sheet.attrib.get("name")
        if rel_id and name and rel_id in rel_targets:
            names[rel_targets[rel_id]] = name
    return names


def _read_xlsx_text(path: Path, max_rows_per_sheet: int = 250) -> str:
    with zipfile.ZipFile(path) as zf:
        shared = _xlsx_shared_strings(zf)
        sheet_names = _xlsx_sheet_names(zf)
        sheets = sorted(
            [name for name in zf.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml$", name)],
            key=_natural_key,
        )
        blocks = []
        for idx, name in enumerate(sheets, 1):
            try:
                root = ElementTree.fromstring(zf.read(name))
            except ElementTree.ParseError:
                continue
            rows = []
            for row in root.iter():
                if row.tag.rsplit("}", 1)[-1] != "row":
                    continue
                values = []
                for cell in row:
                    if cell.tag.rsplit("}", 1)[-1] != "c":
                        continue
                    cell_type = cell.attrib.get("t")
                    value = ""
                    for child in cell:
                        child_tag = child.tag.rsplit("}", 1)[-1]
                        if child_tag == "v" and child.text:
                            if cell_type == "s":
                                try:
                                    value = shared[int(child.text)]
                                except (ValueError, IndexError):
                                    value = child.text
                            else:
                                value = child.text
                        elif child_tag == "is":
                            inline_text = _xml_text_nodes(ElementTree.tostring(child))
                            value = " ".join(inline_text)
                    if value:
                        values.append(value)
                if values:
                    rows.append(" | ".join(values))
                if len(rows) >= max_rows_per_sheet:
                    rows.append(f"[truncated after {max_rows_per_sheet} rows]")
                    break
            if rows:
                label = sheet_names.get(name, f"sheet {idx}")
                blocks.append(f"[sheet: {label}; source: {name}]\n" + "\n".join(rows))
    return "\n\n".join(blocks)


def _format_sheet_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _read_xls_text(path: Path, max_rows_per_sheet: int = 250) -> str:
    try:
        import xlrd
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("Для XLS установите зависимость xlrd") from exc
    workbook = xlrd.open_workbook(str(path), on_demand=True)
    blocks = []
    for sheet in workbook.sheets():
        rows = []
        for row_index in range(min(sheet.nrows, max_rows_per_sheet)):
            values = [
                formatted
                for col_index in range(sheet.ncols)
                if (formatted := _format_sheet_cell(sheet.cell_value(row_index, col_index)))
            ]
            if values:
                rows.append(" | ".join(values))
        if sheet.nrows > max_rows_per_sheet:
            rows.append(f"[truncated after {max_rows_per_sheet} rows]")
        if rows:
            blocks.append(f"[sheet: {sheet.name}; source: {path.name}]\n" + "\n".join(rows))
    return "\n\n".join(blocks)


def _read_csv_text(path: Path) -> str:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    rows = []
    for row in csv.reader(raw.splitlines()):
        if any(cell.strip() for cell in row):
            rows.append(" | ".join(cell.strip() for cell in row))
    return f"[sheet: csv; source: {path.name}]\n" + "\n".join(rows)


def read_document_text(path: Path) -> tuple[dict[str, Any], str]:
    suffix = path.suffix.lower()
    if suffix in {".md", ".txt", ".json"}:
        raw = path.read_text(encoding="utf-8", errors="ignore")
        return parse_front_matter(raw)
    if suffix == ".csv":
        return {}, _read_csv_text(path)
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("Для PDF установите зависимость pypdf") from exc
        reader = PdfReader(str(path))
        blocks = []
        for idx, page in enumerate(reader.pages, 1):
            page_text = page.extract_text() or ""
            if page_text.strip():
                blocks.append(f"[page {idx}]\n{page_text}")
        text = "\n".join(blocks)
        if not text.strip() and detect_conversion_capabilities().can_ocr_pdf:
            ocr_text = ocr_pdf_text(path)
            if ocr_text.strip():
                return {"ocr": "ocrmypdf_sidecar"}, f"[page 1]\n{ocr_text}"
        return {}, text
    if suffix == ".doc":
        converted = convert_legacy_office(path)
        return {"converted_from": str(path), "conversion": "soffice_doc_to_docx"}, _read_docx_like_text(converted)
    if suffix in {".docx", ".docm"}:
        return {}, _read_docx_like_text(path)
    if suffix == ".xls":
        direct_error: Exception | None = None
        try:
            text = _read_xls_text(path)
            if text.strip():
                return {"xls_reader": "xlrd"}, text
        except Exception as exc:
            direct_error = exc
        try:
            converted = convert_legacy_office(path)
        except RuntimeError as exc:
            if direct_error is not None:
                raise RuntimeError(f"Direct XLS parse failed: {str(direct_error)[:250]}; {exc}") from exc
            raise
        if converted.suffix.lower() == ".csv":
            return {"converted_from": str(path), "conversion": "soffice_xls_to_csv"}, _read_csv_text(converted)
        return {"converted_from": str(path), "conversion": "soffice_xls_to_xlsx"}, _read_xlsx_text(converted)
    if suffix == ".ppt":
        converted = convert_legacy_office(path)
        return {"converted_from": str(path), "conversion": "soffice_ppt_to_pptx"}, _read_pptx_text(converted)
    if suffix == ".pptx":
        return {}, _read_pptx_text(path)
    if suffix == ".xlsx":
        return {}, _read_xlsx_text(path)
    raise RuntimeError(f"Формат {suffix} пока не поддержан MVP-ингестором")


def detect_language(text: str) -> str:
    cyr = len(re.findall(r"[а-яА-ЯёЁ]", text))
    lat = len(re.findall(r"[a-zA-Z]", text))
    if cyr > lat:
        return "ru"
    if lat > 0:
        return "en"
    return "unknown"
