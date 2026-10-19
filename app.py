import ast
import io
import json
import zipfile
from datetime import datetime
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024

MAX_FILES = 500
MAX_FILE_BYTES = 1024 * 1024

DEMO_FILES = {
    "main.py": '''
import os

def process_data(items):
    # TODO: validate input
    result = []
    for item in items:
        if item:
            if isinstance(item, str):
                if len(item) > 2:
                    result.append(item.upper())
    return result

def calculate_total(values):
    total = 0
    for value in values:
        total += value
    return total

class DataManager:
    def load(self):
        pass
''',
    "utils.py": '''
def greet(name):
    return "Hello, " + name

def find_user(users, user_id):
    for user in users:
        if user.get("id") == user_id:
            return user
    return None

# FIXME: improve error handling
'''
}


def analyze_source(filename, source):
    issues = []
    metrics = {
        "functions": 0,
        "classes": 0,
        "complexity": 0,
        "long_functions": 0,
        "deep_nesting": 0,
        "todos": 0,
    }

    lines = source.splitlines()

    for number, line in enumerate(lines, 1):
        if "TODO" in line.upper():
            metrics["todos"] += 1
            issues.append({
                "severity": "info",
                "file": filename,
                "line": number,
                "title": "TODO comment",
                "detail": line.strip()[:180] or "Follow-up work is noted."
            })
        if "FIXME" in line.upper():
            issues.append({
                "severity": "warning",
                "file": filename,
                "line": number,
                "title": "FIXME comment",
                "detail": line.strip()[:180] or "A potential issue is noted."
            })

    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        issues.append({
            "severity": "error",
            "file": filename,
            "line": error.lineno or 1,
            "title": "Python syntax error",
            "detail": error.msg
        })
        return {
            "file": filename,
            "lines": len(lines),
            "functions": 0,
            "classes": 0,
            "complexity": 0,
            "issues": issues,
            "parse_error": True,
        }

    metrics["classes"] = sum(
        isinstance(node, ast.ClassDef) for node in ast.walk(tree)
    )

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            metrics["functions"] += 1
            end_line = getattr(node, "end_lineno", node.lineno)
            function_length = end_line - node.lineno + 1

            if function_length > 40:
                metrics["long_functions"] += 1
                issues.append({
                    "severity": "warning",
                    "file": filename,
                    "line": node.lineno,
                    "title": "Long function",
                    "detail": (
                        f"'{node.name}' spans {function_length} lines. "
                        "Consider splitting it into smaller functions."
                    )
                })

            complexity = 1 + sum(
                isinstance(child, (
                    ast.If, ast.For, ast.AsyncFor, ast.While,
                    ast.ExceptHandler, ast.IfExp, ast.Assert
                ))
                or (
                    isinstance(child, ast.BoolOp)
                    and isinstance(child.op, (ast.And, ast.Or))
                )
                or isinstance(child, (ast.comprehension,))
                for child in ast.walk(node)
            )
            metrics["complexity"] += complexity

            max_depth = [0]

            def measure_depth(current, depth=0):
                if isinstance(current, (ast.If, ast.For, ast.AsyncFor, ast.While,
                                         ast.With, ast.AsyncWith, ast.Try)):
                    depth += 1
                    max_depth[0] = max(max_depth[0], depth)
                for child in ast.iter_child_nodes(current):
                    measure_depth(child, depth)

            measure_depth(node)

            if max_depth[0] >= 4:
                metrics["deep_nesting"] += 1
                issues.append({
                    "severity": "warning",
                    "file": filename,
                    "line": node.lineno,
                    "title": "Deep nesting",
                    "detail": (
                        f"'{node.name}' has nesting depth {max_depth[0]}. "
                        "Consider simplifying the control flow."
                    )
                })

    return {
        "file": filename,
        "lines": len(lines),
        "functions": metrics["functions"],
        "classes": metrics["classes"],
        "complexity": metrics["complexity"],
        "issues": issues,
        "parse_error": False,
    }


def scan_files(files):
    results = []
    for filename, source in files.items():
        results.append(analyze_source(filename, source))

    all_issues = [
        issue for result in results for issue in result["issues"]
    ]

    return {
        "project": "OpenTrace Analysis",
        "generated_at": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
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


PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenTrace — Codebase Intelligence</title>
<style>
:root{color-scheme:dark;--bg:#0a0e17;--panel:#111827;--line:#263247;
--muted:#91a0b8;--text:#edf3ff;--blue:#69a7ff;--green:#52e0b0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{padding:22px 5%;border-bottom:1px solid var(--line);
display:flex;align-items:center;justify-content:space-between;gap:16px}
.brand{font-size:23px;font-weight:800;letter-spacing:-.8px}
.brand span{color:var(--blue)}
.tag{font-size:12px;color:var(--green);border:1px solid #245c51;
padding:7px 10px;border-radius:20px}
main{max-width:1120px;margin:42px auto;padding:0 22px}
h1{font-size:clamp(32px,5vw,52px);letter-spacing:-1.8px;margin:0 0 12px}
h1 span{color:var(--blue)}
p{color:var(--muted);line-height:1.7}
.hero{margin-bottom:28px}
.panel,.metric,.file-card{background:var(--panel);border:1px solid var(--line);
border-radius:16px;padding:22px}
.upload{display:grid;grid-template-columns:1.4fr 1fr;gap:16px}
.drop{border:1px dashed #435573;border-radius:12px;padding:24px}
label{display:block;font-weight:650;margin-bottom:12px}
input[type=file]{width:100%;color:var(--muted);margin:8px 0 18px}
button,.button{background:var(--blue);color:#07101e;border:0;border-radius:9px;
padding:12px 16px;font-weight:750;cursor:pointer;text-decoration:none;
display:inline-block;font-size:14px}
button:hover,.button:hover{filter:brightness(1.1)}
.secondary{background:#202c40;color:var(--text)}
.small{font-size:12px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));
gap:13px;margin:20px 0}
.metric{padding:19px}
.metric strong{font-size:30px;display:block;margin:8px 0}
.metric span{font-size:12px;color:var(--muted)}
.section-head{display:flex;align-items:center;justify-content:space-between;
gap:12px;flex-wrap:wrap;margin:30px 0 15px}
.section-head h2{margin:0;font-size:21px}
.filters{display:flex;gap:7px;flex-wrap:wrap}
.filters button{padding:8px 11px}
.files{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.file-card{padding:17px}
.file-card strong{overflow-wrap:anywhere}
.file-meta{color:var(--muted);font-size:13px;line-height:1.8;margin-top:9px}
.issue{border:1px solid var(--line);border-radius:12px;padding:15px;margin-bottom:10px}
.issue-top{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.severity{font-size:11px;text-transform:uppercase;letter-spacing:.6px;
font-weight:800;border-radius:5px;padding:5px 7px}
.error{background:#51252d;color:#ffb6bf}
.warning{background:#49391c;color:#ffd58a}
.info{background:#183858;color:#a7d3ff}
.issue p{margin:9px 0 0;font-size:14px;overflow-wrap:anywhere}
.issue small{color:var(--muted)}
.empty{padding:25px;text-align:center;color:var(--muted)}
footer{border-top:1px solid var(--line);margin-top:48px;padding:24px 5%;
color:var(--muted);font-size:12px;text-align:center}
.notice{background:#172337;border-radius:10px;padding:13px;color:#b8c9e6;
font-size:13px;line-height:1.6;margin-top:15px}
@media(max-width:720px){.upload{grid-template-columns:1fr}.grid{
grid-template-columns:repeat(2,minmax(0,1fr))}.files{grid-template-columns:1fr}
header{padding:18px 5%}main{margin-top:30px}}
</style>
</head>
<body>
<header>
  <div class="brand">◈ Open<span>Trace</span></div>
  <div class="tag">● CODEBASE ANALYSIS</div>
</header>
<main>
  <section class="hero">
    <h1>Understand your<br><span>codebase.</span></h1>
    <p>Inspect Python projects, discover maintainability signals, and turn code
    structure into actionable insights. Your source code is analyzed locally
    by this application.</p>
  </section>

  <section class="panel">
    <h2 style="margin-top:0">Analyze a Python project</h2>
    <p class="small">Upload a ZIP containing .py files. OpenTrace reads source
    code as text and parses its syntax; it does not execute uploaded code.</p>
    <div class="upload">
      <form class="drop" action="/scan" method="post" enctype="multipart/form-data">
        <label for="project">Project ZIP file</label>
        <input id="project" type="file" name="project" accept=".zip" required>
        <button type="submit">Analyze project ↗</button>
      </form>
      <div class="drop">
        <label>Explore a sample project</label>
        <p class="small">See how the report works using built-in example code.</p>
        <a class="button secondary" href="/demo">Run sample analysis</a>
      </div>
    </div>
    <div class="notice">Prototype note: these are static code-quality signals,
    not proof of security or full code correctness. Do not upload confidential
    source code to a shared or publicly hosted instance.</div>
  </section>

  {% if report %}
  <div class="section-head">
    <h2>Analysis overview</h2>
    <button onclick="downloadReport()">Export JSON ↓</button>
  </div>
  <div class="grid">
    <div class="metric"><span>FILES SCANNED</span><strong>{{ report.files_scanned }}</strong></div>
    <div class="metric"><span>LINES OF CODE</span><strong>{{ report.total_lines }}</strong></div>
    <div class="metric"><span>FUNCTIONS</span><strong>{{ report.total_functions }}</strong></div>
    <div class="metric"><span>CLASSES</span><strong>{{ report.total_classes }}</strong></div>
  </div>
  <div class="grid">
    <div class="metric"><span>ERRORS</span><strong style="color:#ff8e9a">{{ report.errors }}</strong></div>
    <div class="metric"><span>WARNINGS</span><strong style="color:#ffd58a">{{ report.warnings }}</strong></div>
    <div class="metric"><span>INFO</span><strong style="color:#a7d3ff">{{ report.info }}</strong></div>
    <div class="metric"><span>COMPLEXITY ESTIMATE</span><strong>{{ report.total_complexity }}</strong></div>
  </div>

  <div class="section-head">
    <h2>Source files</h2>
    <span class="small" style="color:var(--muted)">Per-file overview</span>
  </div>
  <div class="files">
    {% for file in report.files %}
    <div class="file-card">
      <strong>⌘ {{ file.file }}</strong>
      <div class="file-meta">
        {{ file.lines }} lines · {{ file.functions }} functions ·
        {{ file.classes }} classes · complexity {{ file.complexity }}
        {% if file.parse_error %}<br><span style="color:#ff8e9a">Syntax parsing failed</span>{% endif %}
      </div>
    </div>
    {% endfor %}
  </div>

  <div class="section-head">
    <h2>Findings</h2>
    <div class="filters">
      <button class="secondary" onclick="filterIssues('all')">All</button>
      <button class="secondary" onclick="filterIssues('error')">Errors</button>
      <button class="secondary" onclick="filterIssues('warning')">Warnings</button>
      <button class="secondary" onclick="filterIssues('info')">Info</button>
    </div>
  </div>
  <div id="issues">
    {% for issue in report.issues %}
    <article class="issue" data-severity="{{ issue.severity }}">
      <div class="issue-top">
        <span class="severity {{ issue.severity }}">{{ issue.severity }}</span>
        <strong>{{ issue.title }}</strong>
      </div>
      <p>{{ issue.detail }}</p>
      <small>{{ issue.file }} · line {{ issue.line }}</small>
    </article>
    {% else %}
    <div class="empty">No findings for the current checks.</div>
    {% endfor %}
  </div>
  {% endif %}
</main>
<footer>OpenTrace · Open-source code intelligence · Built for developers</footer>
<script>
const reportData = {{ report|tojson if report else 'null' }};
function downloadReport(){
  if(!reportData)return;
  const blob=new Blob([JSON.stringify(reportData,null,2)],
    {type:"application/json"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");
  a.href=url;a.download="opentrace-report.json";a.click();
  URL.revokeObjectURL(url);
}
function filterIssues(level){
  document.querySelectorAll(".issue").forEach(el=>{
    el.style.display=(level==="all"||el.dataset.severity===level)?"":"none";
  });
}
</script>
</body>
</html>
"""


@app.get("/")
def index():
    return render_template_string(PAGE, report=None)


@app.get("/demo")
def demo():
    report = scan_files(DEMO_FILES)
    return render_template_string(PAGE, report=report)


@app.post("/scan")
def scan():
    upload = request.files.get("project")
    if not upload or not upload.filename:
        return "Please select a ZIP file.", 400

    if not upload.filename.lower().endswith(".zip"):
        return "Please upload a .zip file containing Python source files.", 400

    data = upload.read(app.config["MAX_CONTENT_LENGTH"] + 1)
    if len(data) > app.config["MAX_CONTENT_LENGTH"]:
        return "Upload is too large. Maximum size is 12 MB.", 413

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return "This ZIP file could not be opened.", 400

    python_files = {}
    try:
        for entry in archive.infolist():
            if entry.is_dir() or not entry.filename.endswith(".py"):
                continue
            if len(python_files) >= MAX_FILES:
                break
            if entry.file_size > MAX_FILE_BYTES:
                continue
            if entry.file_size < 0:
                continue

            # Ignore absolute paths and traversal-like ZIP entries.
            parts = entry.filename.replace("\\", "/").split("/")
            if entry.filename.startswith("/") or ".." in parts:
                continue

            try:
                raw = archive.read(entry)
                if len(raw) > MAX_FILE_BYTES:
                    continue
                source = raw.decode("utf-8")
            except (UnicodeDecodeError, zipfile.BadZipFile, OSError, RuntimeError):
                continue

            python_files[entry.filename] = source
    finally:
        archive.close()

    if not python_files:
        return (
            "No readable Python (.py) files found. "
            "Upload a ZIP containing Python source files.",
            400,
        )

    report = scan_files(python_files)
    return render_template_string(PAGE, report=report)


@app.errorhandler(413)
def too_large(_error):
    return "Upload exceeds the 12 MB limit.", 413


if __name__ == "__main__":
    print("OpenTrace running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
