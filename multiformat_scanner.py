import csv
import io
import json
import zipfile
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath

MAX_FILES = 500
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_EXPANDED_BYTES = 24 * 1024 * 1024

CODE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".h", ".cpp",
    ".hpp", ".cs", ".go", ".rs", ".php", ".rb", ".swift", ".kt",
    ".html", ".css", ".scss", ".vue", ".svelte", ".sh", ".bash",
    ".sql", ".r", ".m", ".pl", ".lua", ".dart", ".json", ".xml",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".csv",
    ".tsv", ".txt", ".md", ".rst", ".log", ".properties",
    ".gradle", ".make", ".dockerfile",
}

def issue(severity, filename, title, detail, line=1):
    return {
        "severity": severity,
        "file": filename,
        "line": line,
        "title": title,
        "detail": str(detail)[:300],
    }

def result(filename, kind, summary, lines=0, issues=None,
           functions=0, classes=0, complexity=0, parse_error=False):
    return {
        "file": filename,
        "format": kind,
        "summary": summary,
        "lines": lines,
        "functions": functions,
        "classes": classes,
        "complexity": complexity,
        "issues": issues or [],
        "parse_error": parse_error,
    }

def text_analysis(filename, raw):
    ext = PurePosixPath(filename.lower()).suffix
    try:
        source = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return result(
            filename, ext or "unknown",
            "Not readable as UTF-8 text; only basic metadata is available.",
            issues=[issue("info", filename, "Binary or unsupported text",
                          "No file contents were executed.")],
        )

    lines = source.splitlines()
    issues = []

    for number, line in enumerate(lines, 1):
        upper = line.upper()
        if "TODO" in upper:
            issues.append(issue("info", filename, "TODO comment",
                                line.strip() or "Follow-up work noted.", number))
        if "FIXME" in upper:
            issues.append(issue("warning", filename, "FIXME comment",
                                line.strip() or "Potential issue noted.", number))
        if len(line) > 200:
            issues.append(issue("info", filename, "Long line",
                                f"Line contains {len(line)} characters.", number))

    summary = f"Readable text; {len(lines)} lines."
    parse_error = False

    try:
        if ext == ".json":
            json.loads(source)
            summary = "Valid JSON syntax."
        elif ext in {".xml", ".svg"}:
            ET.fromstring(source)
            summary = "Valid XML syntax."
        elif ext in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}:
            summary = "Text configuration file; format-specific validation is limited."
        elif ext in {".csv", ".tsv"}:
            delimiter = "\t" if ext == ".tsv" else ","
            rows = list(csv.reader(io.StringIO(source), delimiter=delimiter))
            summary = f"Delimited data; {len(rows)} rows detected."
        elif ext in {".html", ".htm", ".svg"}:
            if "<script" in source.lower():
                issues.append(issue(
                    "warning", filename, "Embedded script found",
                    "Review script content manually; this is not proof of malicious behavior."
                ))
        elif ext in {".js", ".jsx", ".ts", ".tsx", ".sh", ".bash"}:
            if "eval(" in source or "exec(" in source:
                issues.append(issue(
                    "warning", filename, "Dynamic execution pattern",
                    "Review dynamic code execution calls in context."
                ))
        elif ext in {".sql"}:
            if "SELECT *" in source.upper():
                issues.append(issue(
                    "info", filename, "SELECT * query",
                    "Consider selecting only the columns required."
                ))
    except (ValueError, csv.Error, ET.ParseError) as exc:
        parse_error = True
        issues.append(issue(
            "error", filename, "Format validation failed",
            f"{type(exc).__name__}: {exc}"
        ))
        summary = "Format validation failed."

    return result(filename, ext.lstrip(".").upper() or "TEXT",
                  summary, len(lines), issues, parse_error=parse_error)

def analyze_bytes(filename, raw, python_analyzer):
    ext = PurePosixPath(filename.lower()).suffix
    if len(raw) > MAX_FILE_BYTES:
        return result(
            filename, ext.lstrip(".").upper() or "FILE",
            "Skipped: file exceeds the 1 MB per-file analysis limit.",
            issues=[issue("warning", filename, "File size limit",
                          "This file was not analyzed.")],
        )

    if ext == ".py":
        try:
            source = raw.decode("utf-8-sig")
            item = python_analyzer(filename, source)
            item["format"] = "PYTHON"
            item["summary"] = "Python source analyzed with AST-based checks."
            return item
        except UnicodeDecodeError:
            return result(filename, "PYTHON", "Python source is not UTF-8 text.",
                          issues=[issue("error", filename, "Text decoding failed",
                                        "Could not read this file as UTF-8.")])

    if ext == ".pdf":
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(raw), strict=False)
            pages = reader.pages[:100]
            text = "\n".join((page.extract_text() or "") for page in pages)
            issues = []
            if not text.strip():
                issues.append(issue(
                    "info", filename, "No extractable text",
                    "This PDF may be scanned or image-only. OCR is not enabled."
                ))
            if len(reader.pages) > 100:
                issues.append(issue("info", filename, "Page limit",
                                    "Only the first 100 pages were inspected."))
            return result(filename, "PDF",
                          f"{len(reader.pages)} pages; text extraction attempted on up to 100.",
                          len(text.splitlines()), issues)
        except Exception as exc:
            return result(filename, "PDF", "Could not safely read PDF contents.",
                          issues=[issue("error", filename, "PDF read failed",
                                        type(exc).__name__)])

    if ext == ".docx":
        try:
            from docx import Document
            doc = Document(io.BytesIO(raw))
            text = "\n".join(p.text for p in doc.paragraphs)
            return result(filename, "DOCX",
                          f"Word document; {len(doc.paragraphs)} paragraphs and "
                          f"{len(doc.tables)} tables.",
                          len(text.splitlines()),
                          [issue("info", filename, "Document inspected",
                                 "Text and paragraph metadata inspected; macros and embedded objects are not analyzed.")])
        except Exception as exc:
            return result(filename, "DOCX", "Could not read Word document.",
                          issues=[issue("error", filename, "DOCX read failed",
                                        type(exc).__name__)])

    if ext == ".xlsx":
        try:
            from openpyxl import load_workbook
            book = load_workbook(io.BytesIO(raw), read_only=True,
                                 data_only=True)
            details = []
            for sheet in book.worksheets[:30]:
                rows = 0
                for _ in sheet.iter_rows(values_only=True):
                    rows += 1
                    if rows >= 1000:
                        break
                details.append(f"{sheet.title}: up to {rows} rows inspected")
            book.close()
            return result(filename, "XLSX",
                          f"{len(book.sheetnames)} worksheets; " + "; ".join(details),
                          issues=[issue("info", filename, "Spreadsheet inspected",
                                        "Read-only inspection; formulas and macros are not security-validated.")])
        except Exception as exc:
            return result(filename, "XLSX", "Could not read spreadsheet.",
                          issues=[issue("error", filename, "XLSX read failed",
                                        type(exc).__name__)])

    if ext == ".pptx":
        try:
            from pptx import Presentation
            deck = Presentation(io.BytesIO(raw))
            text = []
            for slide in deck.slides[:200]:
                for shape in slide.shapes:
                    if getattr(shape, "has_text_frame", False):
                        text.append(shape.text)
            return result(filename, "PPTX",
                          f"Presentation; {len(deck.slides)} slides.",
                          len("\n".join(text).splitlines()),
                          [issue("info", filename, "Presentation inspected",
                                 "Slide text inspected; embedded objects and macros are not analyzed.")])
        except Exception as exc:
            return result(filename, "PPTX", "Could not read presentation.",
                          issues=[issue("error", filename, "PPTX read failed",
                                        type(exc).__name__)])

    if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff"}:
        try:
            from PIL import Image
            with Image.open(io.BytesIO(raw)) as image:
                image.verify()
            with Image.open(io.BytesIO(raw)) as image:
                return result(filename, "IMAGE",
                              f"{image.format} image; {image.width} × {image.height}; "
                              f"{getattr(image, 'n_frames', 1)} frame(s).",
                              issues=[issue("info", filename, "Image metadata inspected",
                                            "OCR and image-content classification are not enabled.")])
        except Exception as exc:
            return result(filename, "IMAGE", "Could not validate image.",
                          issues=[issue("error", filename, "Image read failed",
                                        type(exc).__name__)])

    if ext in {".exe", ".dll", ".so", ".dylib", ".bin", ".wasm", ".jar"}:
        if raw.startswith(b"MZ"):
            signature = "Windows PE-style MZ signature"
        elif raw.startswith(b"\x7fELF"):
            signature = "ELF executable signature"
        elif raw.startswith(b"\xfe\xed\xfa") or raw.startswith(b"\xcf\xfa\xed\xfe"):
            signature = "Possible Mach-O binary signature"
        elif raw.startswith(b"PK\x03\x04") and ext == ".jar":
            signature = "ZIP-based Java archive signature"
        else:
            signature = "No recognized signature at file start"
        return result(filename, "BINARY",
                      f"{signature}; {len(raw)} bytes. Not executed.",
                      issues=[issue("info", filename, "Static binary check only",
                                    "No disassembly, malware verdict, or runtime execution was performed.")])

    if ext in CODE_EXTENSIONS or ext in {".py", ".htm"} or not ext:
        return text_analysis(filename, raw)

    return result(filename, ext.lstrip(".").upper() or "UNKNOWN",
                  f"Unsupported format; {len(raw)} bytes. Basic metadata only.",
                  issues=[issue("info", filename, "Format not deeply analyzed",
                                "This file type is not supported by the current analyzer.")])

def safe_name(name):
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if normalized.startswith("/") or ".." in path.parts:
        return None
    return str(path)

def scan_uploads(uploads, python_analyzer):
    candidates = []
    issues = []
    expanded = 0

    for name, raw in uploads:
        clean = safe_name(name)
        if not clean or not clean.strip("."):
            issues.append(issue("warning", str(name), "Unsafe filename",
                                "This entry was skipped."))
            continue

        if clean.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    for entry in archive.infolist():
                        if entry.is_dir():
                            continue
                        member = safe_name(entry.filename)
                        if not member:
                            continue
                        if len(candidates) >= MAX_FILES:
                            break
                        if entry.file_size < 0 or entry.file_size > MAX_FILE_BYTES:
                            continue
                        expanded += entry.file_size
                        if expanded > MAX_EXPANDED_BYTES:
                            issues.append(issue(
                                "warning", clean, "Archive expansion limit",
                                "Remaining archive entries were skipped."
                            ))
                            break
                        try:
                            member_data = archive.read(entry)
                        except (RuntimeError, OSError, zipfile.BadZipFile):
                            issues.append(issue("warning", member, "Archive entry skipped",
                                                "The entry could not be read."))
                            continue
                        if len(member_data) <= MAX_FILE_BYTES:
                            candidates.append((f"{clean}/{member}", member_data))
            except (zipfile.BadZipFile, OSError):
                issues.append(issue("error", clean, "Invalid ZIP archive",
                                    "This archive could not be opened."))
            continue

        expanded += len(raw)
        if expanded > MAX_EXPANDED_BYTES:
            issues.append(issue("warning", clean, "Total size limit",
                                "Remaining files were skipped."))
            break
        candidates.append((clean, raw))
        if len(candidates) >= MAX_FILES:
            break

    results = [analyze_bytes(name, raw, python_analyzer)
               for name, raw in candidates[:MAX_FILES]]
    all_issues = issues + [i for item in results for i in item["issues"]]

    return {
        "project": "OpenTrace Analysis",
        "generated_at": __import__("datetime").datetime.now().astimezone().isoformat(timespec="seconds"),
        "files_scanned": len(results),
        "total_lines": sum(r["lines"] for r in results),
        "total_functions": sum(r["functions"] for r in results),
        "total_classes": sum(r["classes"] for r in results),
        "total_complexity": sum(r["complexity"] for r in results),
        "errors": sum(i["severity"] == "error" for i in all_issues),
        "warnings": sum(i["severity"] == "warning" for i in all_issues),
        "info": sum(i["severity"] == "info" for i in all_issues),
        "files": results,
        "issues": all_issues,
    }
