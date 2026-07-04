from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ConversionCapabilities:
    soffice: str | None
    unrar: str | None
    tesseract: str | None
    ocrmypdf: str | None
    seven_zip: str | None

    @property
    def can_convert_legacy_office(self) -> bool:
        return self.soffice is not None

    @property
    def can_extract_rar(self) -> bool:
        return self.unrar is not None

    @property
    def can_ocr_pdf(self) -> bool:
        return self.ocrmypdf is not None


def detect_conversion_capabilities() -> ConversionCapabilities:
    return ConversionCapabilities(
        soffice=shutil.which("soffice") or shutil.which("libreoffice"),
        unrar=shutil.which("unrar"),
        tesseract=shutil.which("tesseract"),
        ocrmypdf=shutil.which("ocrmypdf"),
        seven_zip=shutil.which("7z") or shutil.which("7zz"),
    )


SPLIT_ARCHIVE_PART_RE = re.compile(r"\.(?P<number>\d{3})$", flags=re.IGNORECASE)


def split_archive_part_number(path: Path) -> int | None:
    match = SPLIT_ARCHIVE_PART_RE.search(path.name)
    if not match:
        return None
    return int(match.group("number"))


def split_archive_base_name(path: Path) -> str | None:
    if split_archive_part_number(path) is None:
        return None
    return path.name[:-4]


def split_archive_parts(first_part: Path) -> list[Path]:
    base_name = split_archive_base_name(first_part)
    if base_name is None:
        return []
    parts = [
        candidate
        for candidate in first_part.parent.iterdir()
        if candidate.is_file()
        and candidate.name.startswith(f"{base_name}.")
        and split_archive_part_number(candidate) is not None
    ]
    parts.sort(key=lambda item: split_archive_part_number(item) or 0)
    return parts


def has_consecutive_split_parts(first_part: Path) -> bool:
    parts = split_archive_parts(first_part)
    if len(parts) < 2:
        return False
    numbers = [split_archive_part_number(part) for part in parts]
    return numbers == list(range(1, len(parts) + 1))


def reconstruct_split_archive(first_part: Path, target_dir: Path) -> Path:
    part_number = split_archive_part_number(first_part)
    if part_number != 1:
        raise RuntimeError("Split archive reconstruction must start from the .001 part")
    if not has_consecutive_split_parts(first_part):
        raise RuntimeError(f"Split archive parts are missing or non-consecutive for {first_part.name}")
    base_name = split_archive_base_name(first_part)
    if base_name is None:
        raise RuntimeError(f"Cannot determine split archive base name for {first_part.name}")
    target_dir.mkdir(parents=True, exist_ok=True)
    reconstructed = target_dir / base_name
    with reconstructed.open("wb") as out:
        for part in split_archive_parts(first_part):
            with part.open("rb") as src:
                shutil.copyfileobj(src, out)
    return reconstructed


def ocr_pdf_text(path: Path) -> str:
    capabilities = detect_conversion_capabilities()
    if not capabilities.ocrmypdf:
        raise RuntimeError("PDF OCR requires OCRmyPDF")
    tmpdir = Path(tempfile.mkdtemp(prefix="rdkg-ocr-"))
    output_pdf = tmpdir / f"{path.stem}.ocr.pdf"
    sidecar = tmpdir / f"{path.stem}.txt"
    cmd = [
        capabilities.ocrmypdf,
        "--skip-text",
        "--sidecar",
        str(sidecar),
        str(path),
        str(output_pdf),
    ]
    completed = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=900)
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(f"OCRmyPDF failed for {path.name}: {message[:500]}")
    if sidecar.exists():
        return sidecar.read_text(encoding="utf-8", errors="ignore")
    return ""


def convert_legacy_office(path: Path) -> Path:
    capabilities = detect_conversion_capabilities()
    if not capabilities.soffice:
        raise RuntimeError("Legacy Office conversion requires LibreOffice/soffice")
    suffix = path.suffix.lower()
    target_formats = {".doc": ["docx"], ".xls": ["xlsx", "csv"], ".ppt": ["pptx"]}.get(suffix)
    if target_formats is None:
        raise RuntimeError(f"Legacy Office conversion is not configured for {suffix}")
    tmpdir = Path(tempfile.mkdtemp(prefix="rdkg-office-convert-"))
    user_installation = tmpdir / "lo-profile"
    home_dir = tmpdir / "home"
    xdg_cache_dir = tmpdir / "xdg-cache"
    fontconfig_dir = tmpdir / "fontconfig"
    user_installation.mkdir(parents=True, exist_ok=True)
    home_dir.mkdir(parents=True, exist_ok=True)
    xdg_cache_dir.mkdir(parents=True, exist_ok=True)
    fontconfig_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home_dir),
            "XDG_CACHE_HOME": str(xdg_cache_dir),
            "FONTCONFIG_PATH": str(fontconfig_dir),
        }
    )
    errors: list[str] = []
    for target_format in target_formats:
        cmd = [
            capabilities.soffice,
            f"-env:UserInstallation={user_installation.as_uri()}",
            "--headless",
            "--convert-to",
            target_format,
            "--outdir",
            str(tmpdir),
            str(path),
        ]
        completed = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            env=env,
        )
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "").strip()
            errors.append(f".{target_format}: {message[:500]}")
            continue
        converted = tmpdir / f"{path.stem}.{target_format}"
        if converted.exists():
            return converted
        candidates = list(tmpdir.glob(f"*.{target_format}"))
        if len(candidates) == 1:
            return candidates[0]
        errors.append(f".{target_format}: no output file produced")
    raise RuntimeError(f"LibreOffice conversion failed for {path.name}: {' | '.join(errors)[:500]}")


def extract_rar_archive(rar_path: Path, target_dir: Path) -> Path:
    capabilities = detect_conversion_capabilities()
    if not capabilities.unrar:
        raise RuntimeError("RAR extraction requires unrar")
    extract_root = target_dir / rar_path.stem
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [capabilities.unrar, "x", "-idq", "-o+", str(rar_path), str(extract_root)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
    )
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(f"RAR extraction failed for {rar_path.name}: {message[:500]}")
    return extract_root
