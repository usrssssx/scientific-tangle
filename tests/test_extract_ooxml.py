from pathlib import Path
import sys
from types import SimpleNamespace
import zipfile

from app.converters import ConversionCapabilities, convert_legacy_office
from app.extract import read_document_text


def _write_docx(path, text: str) -> None:
    document_xml = f"""
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
      <w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>
    </w:document>
    """
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("word/document.xml", document_xml)


def _write_xlsx(path) -> None:
    workbook_xml = """
    <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
              xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
      <sheets><sheet name="LegacySheet" sheetId="1" r:id="rId1"/></sheets>
    </workbook>
    """
    rels_xml = """
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
      <Relationship Id="rId1" Target="worksheets/sheet1.xml"/>
    </Relationships>
    """
    sheet_xml = """
    <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
      <sheetData>
        <row r="1"><c t="inlineStr"><is><t>nickel</t></is></c><c><v>0.30</v></c></row>
      </sheetData>
    </worksheet>
    """
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", rels_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)


def test_read_pptx_text_with_slide_marker(tmp_path):
    path = tmp_path / "demo.pptx"
    slide_xml = """
    <p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
           xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
      <p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Циркуляция католита nickel</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld>
    </p:sld>
    """
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("ppt/slides/slide1.xml", slide_xml)

    metadata, text = read_document_text(path)

    assert metadata == {}
    assert "[slide 1" in text
    assert "Циркуляция католита nickel" in text


def test_read_xlsx_text_with_sheet_marker(tmp_path):
    path = tmp_path / "demo.xlsx"
    workbook_xml = """
    <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
              xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
      <sheets><sheet name="Experiments" sheetId="1" r:id="rId1"/></sheets>
    </workbook>
    """
    rels_xml = """
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
      <Relationship Id="rId1" Target="worksheets/sheet1.xml"/>
    </Relationships>
    """
    shared_xml = """
    <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
      <si><t>материал</t></si>
      <si><t>nickel</t></si>
      <si><t>flow velocity</t></si>
    </sst>
    """
    sheet_xml = """
    <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
      <sheetData>
        <row r="1"><c t="s"><v>0</v></c><c t="s"><v>2</v></c></row>
        <row r="2"><c t="s"><v>1</v></c><c><v>0.25</v></c></row>
      </sheetData>
    </worksheet>
    """
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", rels_xml)
        zf.writestr("xl/sharedStrings.xml", shared_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)

    _, text = read_document_text(path)

    assert "[sheet: Experiments" in text
    assert "материал | flow velocity" in text
    assert "nickel | 0.25" in text


def test_read_legacy_doc_uses_soffice_conversion(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy.doc"
    converted = tmp_path / "legacy.docx"
    legacy.write_bytes(b"legacy-doc")
    _write_docx(converted, "Legacy DOC catholyte circulation")

    monkeypatch.setattr("app.extract.convert_legacy_office", lambda path: converted)

    metadata, text = read_document_text(legacy)

    assert metadata["converted_from"] == str(legacy)
    assert metadata["conversion"] == "soffice_doc_to_docx"
    assert "Legacy DOC catholyte circulation" in text


def test_read_legacy_xls_uses_soffice_conversion(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy.xls"
    converted = tmp_path / "legacy.xlsx"
    legacy.write_bytes(b"legacy-xls")
    _write_xlsx(converted)

    monkeypatch.setattr("app.extract.convert_legacy_office", lambda path: converted)

    metadata, text = read_document_text(legacy)

    assert metadata["converted_from"] == str(legacy)
    assert metadata["conversion"] == "soffice_xls_to_xlsx"
    assert "[sheet: LegacySheet" in text
    assert "nickel | 0.30" in text


def test_read_legacy_xls_accepts_soffice_csv_fallback(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy.xls"
    converted = tmp_path / "legacy.csv"
    legacy.write_bytes(b"legacy-xls")
    converted.write_text("parameter,value\ncopper,42\n", encoding="utf-8")

    monkeypatch.setattr("app.extract.convert_legacy_office", lambda path: converted)

    metadata, text = read_document_text(legacy)

    assert metadata["converted_from"] == str(legacy)
    assert metadata["conversion"] == "soffice_xls_to_csv"
    assert "[sheet: csv" in text
    assert "copper | 42" in text


def test_read_legacy_xls_uses_xlrd_direct_reader(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy.xls"
    legacy.write_bytes(b"legacy-xls")

    class FakeSheet:
        name = "Forecast"
        nrows = 2
        ncols = 2

        def cell_value(self, row, col):
            return [["metric", "value"], ["copper", 42.0]][row][col]

    class FakeWorkbook:
        def sheets(self):
            return [FakeSheet()]

    monkeypatch.setitem(sys.modules, "xlrd", SimpleNamespace(open_workbook=lambda *args, **kwargs: FakeWorkbook()))

    metadata, text = read_document_text(legacy)

    assert metadata["xls_reader"] == "xlrd"
    assert "[sheet: Forecast" in text
    assert "copper | 42" in text


def test_legacy_office_conversion_uses_writable_cache_env(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy.xls"
    legacy.write_bytes(b"legacy-xls")
    captured = {}

    monkeypatch.setattr(
        "app.converters.detect_conversion_capabilities",
        lambda: ConversionCapabilities(soffice="/usr/bin/soffice", unrar=None, tesseract=None, ocrmypdf=None, seven_zip=None),
    )

    def fake_run(cmd, **kwargs):
        outdir = tmp_path
        for index, item in enumerate(cmd):
            if item == "--outdir":
                outdir = Path(cmd[index + 1])
                break
        (outdir / "legacy.xlsx").write_bytes(b"converted")
        captured["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("app.converters.subprocess.run", fake_run)

    converted = convert_legacy_office(legacy)

    assert converted.name == "legacy.xlsx"
    assert captured["env"]["HOME"].endswith("/home")
    assert captured["env"]["XDG_CACHE_HOME"].endswith("/xdg-cache")
    assert captured["env"]["FONTCONFIG_PATH"].endswith("/fontconfig")


def test_legacy_xls_conversion_falls_back_to_csv(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy.xls"
    legacy.write_bytes(b"legacy-xls")
    formats = []

    monkeypatch.setattr(
        "app.converters.detect_conversion_capabilities",
        lambda: ConversionCapabilities(soffice="/usr/bin/soffice", unrar=None, tesseract=None, ocrmypdf=None, seven_zip=None),
    )

    def fake_run(cmd, **kwargs):
        target_format = cmd[cmd.index("--convert-to") + 1]
        formats.append(target_format)
        if target_format == "xlsx":
            return SimpleNamespace(returncode=1, stdout="", stderr="Error: no export filter")
        outdir = Path(cmd[cmd.index("--outdir") + 1])
        (outdir / "legacy.csv").write_text("parameter,value\ncopper,42\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("app.converters.subprocess.run", fake_run)

    converted = convert_legacy_office(legacy)

    assert converted.name == "legacy.csv"
    assert formats == ["xlsx", "csv"]
