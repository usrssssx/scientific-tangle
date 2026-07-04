from app.extract import chunk_text_with_locations, extract_entities, extract_numeric_conditions, validate_numeric_hit
from app.extract import read_document_text


def test_extract_entities_ru_en_synonyms():
    text = "Циркуляции католита при электроэкстракции nickel: catholyte flow velocity 0.20 m/s"
    hits = {(h.type, h.canonical) for h in extract_entities(text)}
    assert ("Process", "catholyte_circulation") in hits
    assert ("Process", "electrowinning") in hits
    assert ("Material", "nickel") in hits


def test_extract_entities_keeps_category_overlaps():
    terms = {
        "materials": {"catholyte": ["catholyte"]},
        "processes": {"catholyte_circulation": ["catholyte circulation"]},
    }
    hits = {(h.type, h.canonical) for h in extract_entities("catholyte circulation", terms)}
    assert ("Material", "catholyte") in hits
    assert ("Process", "catholyte_circulation") in hits


def test_extract_numeric_conditions_range_and_limit():
    text = "Сульфаты 200-300 мг/л, сухой остаток ≤1000 мг/дм³, скорость циркуляции 0.20-0.30 м/с"
    hits = extract_numeric_conditions(text)
    assert any(h.unit == "mg_l" and h.min_value == 200.0 and h.max_value == 300.0 for h in hits)
    assert any(h.property == "tds" and h.comparator == "<=" and h.value == 1000.0 for h in hits)
    assert any(h.property == "flow_velocity" and h.unit == "m_s" for h in hits)


def test_extract_numeric_conditions_supports_engineering_units():
    text = "Производительность 2 т/сут, расход раствора 3.6 м3/ч и подпитка 1 л/с."
    hits = extract_numeric_conditions(text)

    assert any(h.unit == "t_day" and h.value == 2.0 for h in hits)
    assert any(h.unit == "m3_h" and h.value == 3.6 for h in hits)
    assert any(h.unit == "l_s" and h.value == 1.0 for h in hits)


def test_chunk_text_with_locations_keeps_page_locator():
    chunks = chunk_text_with_locations("[page 2]\nТемпература 50 °C.\n\n[page 3]\nСкорость 0.2 м/с.")

    assert [chunk.locator for chunk in chunks] == ["page 2", "page 3"]
    assert chunks[0].locator_type == "page"
    assert chunks[0].metadata == {"page": 2}


def test_validate_numeric_hit_flags_impossible_percent():
    hit = extract_numeric_conditions("Извлечение составило 120 %.")[0]
    status, warnings = validate_numeric_hit(hit)

    assert status == "suspicious"
    assert "percent_outside_0_100" in warnings


def test_blank_pdf_does_not_emit_page_marker_only(tmp_path):
    from pypdf import PdfWriter

    path = tmp_path / "blank.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with path.open("wb") as f:
        writer.write(f)

    _, text = read_document_text(path)

    assert text == ""


def test_blank_pdf_uses_ocr_sidecar_when_available(tmp_path, monkeypatch):
    from pypdf import PdfWriter

    from app.converters import ConversionCapabilities

    path = tmp_path / "scan.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with path.open("wb") as f:
        writer.write(f)

    monkeypatch.setattr(
        "app.extract.detect_conversion_capabilities",
        lambda: ConversionCapabilities(soffice=None, unrar=None, tesseract=None, ocrmypdf="/usr/bin/ocrmypdf", seven_zip=None),
    )
    monkeypatch.setattr("app.extract.ocr_pdf_text", lambda pdf_path: "OCR nickel flow velocity 0.20 m/s")

    metadata, text = read_document_text(path)

    assert metadata == {"ocr": "ocrmypdf_sidecar"}
    assert "[page 1]" in text
    assert "OCR nickel flow velocity" in text
