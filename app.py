"""
FORENSTIX 2.0 — Flask Web Application

New in v2.0:
  POST /pivot          — synchronous IOC pivot (run tool(s) against extracted IOC)
  GET  /pivot/stream   — SSE streaming pivot (line-by-line tool output)
  GET  /cases          — list all cases
  POST /cases          — create a case
  GET  /cases/<id>     — get case details + stats
  PUT  /cases/<id>     — update case (name / description / status)
  DELETE /cases/<id>   — delete case
  POST /cases/<id>/files     — add analyze result to a case
  GET  /cases/<id>/files     — list files in a case
  GET  /cases/<id>/iocs      — list IOCs in a case
  POST /cases/<id>/iocs      — manually add an IOC
  GET  /cases/<id>/pivot-results — list all pivot results in a case
  POST /cases/<id>/notes     — add analyst note
  GET  /cases/<id>/notes     — list notes
  GET  /cases/<id>/timeline  — full case timeline

All v1 endpoints are fully preserved.
"""

import os
import json
import datetime
import tempfile
import markdown
from flask import Flask, render_template, request, jsonify, send_file, Response, stream_with_context
from werkzeug.utils import secure_filename

from analyzer import analyze_file
from report_generator import generate_humanized_report
from virustotal import lookup_hash
from comparator import compare_files
import cases as db
from pivot import run_pivot, stream_pivot, IOC_TOOL_MAP

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = tempfile.mkdtemp()


# ═══════════════════════════════════════════════════════════════════════════
# UI
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ═══════════════════════════════════════════════════════════════════════════
# Analysis (v1 compatible)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    try:
        file.save(filepath)
        results = analyze_file(filepath)
        report_md = generate_humanized_report(results)
        report_html = markdown.markdown(report_md, extensions=["tables", "fenced_code"])
        return jsonify({
            "results": results,
            "report_markdown": report_md,
            "report_html": report_html,
        })
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route("/analyze-batch", methods=["POST"])
def analyze_batch():
    files = request.files.getlist("files")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No files uploaded"}), 400
    if len(files) > 20:
        return jsonify({"error": "Maximum 20 files per batch"}), 400

    results_list = []
    saved_paths = []
    try:
        for file in files:
            if file.filename == "":
                continue
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], f"{len(saved_paths)}_{filename}")
            file.save(filepath)
            saved_paths.append(filepath)
            try:
                analysis = analyze_file(filepath)
                report_md = generate_humanized_report(analysis)
                report_html = markdown.markdown(report_md, extensions=["tables", "fenced_code"])
                results_list.append({
                    "results": analysis,
                    "report_markdown": report_md,
                    "report_html": report_html,
                    "status": "success",
                })
            except Exception as e:
                results_list.append({
                    "results": {"metadata": {"filename": file.filename}},
                    "error": str(e),
                    "status": "error",
                })
        return jsonify({
            "batch_results": results_list,
            "total_files": len(results_list),
            "successful": sum(1 for r in results_list if r["status"] == "success"),
            "failed": sum(1 for r in results_list if r["status"] == "error"),
        })
    except Exception as e:
        return jsonify({"error": f"Batch analysis failed: {str(e)}"}), 500
    finally:
        for path in saved_paths:
            if os.path.exists(path):
                os.remove(path)


@app.route("/virustotal/<file_hash>", methods=["GET"])
def virustotal_lookup(file_hash):
    if not file_hash or len(file_hash) not in (32, 40, 64):
        return jsonify({"error": "Invalid hash"}), 400
    return jsonify(lookup_hash(file_hash))


@app.route("/compare", methods=["POST"])
def compare():
    files = request.files.getlist("files")
    valid = [f for f in files if f.filename != ""]
    if len(valid) < 2:
        return jsonify({"error": "Need at least 2 files for comparison"}), 400
    if len(valid) > 10:
        return jsonify({"error": "Maximum 10 files for comparison"}), 400

    analyses = []
    saved_paths = []
    try:
        for file in valid:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], f"cmp_{len(saved_paths)}_{filename}")
            file.save(filepath)
            saved_paths.append(filepath)
            analyses.append(analyze_file(filepath))

        comparison = compare_files(analyses)
        narrative = _generate_comparison_narrative(comparison)
        narrative_html = markdown.markdown(narrative, extensions=["tables", "fenced_code"])
        return jsonify({
            "comparison": comparison,
            "individual_analyses": analyses,
            "narrative_html": narrative_html,
        })
    except Exception as e:
        return jsonify({"error": f"Comparison failed: {str(e)}"}), 500
    finally:
        for path in saved_paths:
            if os.path.exists(path):
                os.remove(path)


@app.route("/export-pdf", methods=["POST"])
def export_pdf():
    try:
        data = request.get_json()
        report_html = data.get("report_html", "")
        results = data.get("results", {})
        filename = results.get("metadata", {}).get("filename", "batch_report")
        report_title = data.get("title", "Digital Forensic Investigation Report")

        pdf_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
    @page {{ margin: 1in; }}
    body {{ font-family:'Segoe UI',Tahoma,sans-serif; font-size:11pt; line-height:1.6;
           color:#1a1a2e; max-width:7.5in; margin:0 auto; }}
    .header {{ border-bottom:3px solid #0f3460; padding-bottom:15px; margin-bottom:25px; }}
    .header h1 {{ color:#0f3460; font-size:22pt; margin:0; letter-spacing:3px; }}
    .header .sub {{ color:#16213e; font-size:10pt; margin-top:5px; }}
    .header .meta {{ color:#666; font-size:9pt; margin-top:8px; }}
    h2 {{ color:#0f3460; font-size:14pt; border-bottom:1px solid #ddd;
         padding-bottom:5px; margin-top:25px; }}
    code {{ background:#f4f4f4; padding:2px 6px; border-radius:3px;
           font-family:Consolas,monospace; font-size:9pt; word-break:break-all; }}
    strong {{ color:#0f3460; }}
    .footer {{ margin-top:40px; padding-top:15px; border-top:1px solid #ddd;
              font-size:8pt; color:#999; text-align:center; }}
</style></head>
<body>
    <div class="header">
        <h1>FORENSTIX 2.0</h1>
        <div class="sub">{report_title}</div>
        <div class="meta">File: {filename} | {datetime.datetime.now().strftime('%B %d, %Y at %I:%M %p')} | v2.0</div>
    </div>
    {report_html}
    <div class="footer">Generated by FORENSTIX v2.0 — For authorized forensic analysis only.</div>
</body></html>"""

        tmp_html = os.path.join(app.config["UPLOAD_FOLDER"], "report.html")
        tmp_pdf = os.path.join(app.config["UPLOAD_FOLDER"], "report.pdf")
        with open(tmp_html, "w") as f:
            f.write(pdf_html)

        try:
            from weasyprint import HTML
            HTML(filename=tmp_html).write_pdf(tmp_pdf)
            return send_file(tmp_pdf, as_attachment=True,
                             download_name=f"FORENSTIX_Report_{filename}.pdf",
                             mimetype="application/pdf")
        except ImportError:
            return send_file(tmp_html, as_attachment=True,
                             download_name=f"FORENSTIX_Report_{filename}.html",
                             mimetype="text/html")
    except Exception as e:
        return jsonify({"error": f"Export failed: {str(e)}"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# IOC Pivot (NEW in v2.0)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/pivot", methods=["POST"])
def pivot():
    """
    Synchronous IOC pivot.

    Request body (JSON):
      ioc_type  string  required  domain | url | email | ip | hash | username
      value     string  required  the IOC to investigate
      tools     array   optional  override default tool list
      timeout   int     optional  per-tool timeout in seconds (default 60)
      case_id   int     optional  if provided, saves results to case
      ioc_id    int     optional  link results to specific case IOC row
    """
    body = request.get_json(silent=True) or {}
    ioc_type = body.get("ioc_type", "").strip().lower()
    value = body.get("value", "").strip()
    tools = body.get("tools")
    timeout = int(body.get("timeout", 60))
    case_id = body.get("case_id")
    ioc_id = body.get("ioc_id")

    if not ioc_type or not value:
        return jsonify({"error": "ioc_type and value are required"}), 400
    if ioc_type not in IOC_TOOL_MAP:
        return jsonify({"error": f"Unknown ioc_type. Valid: {list(IOC_TOOL_MAP)}"}), 400

    results = run_pivot(
        ioc_type=ioc_type,
        value=value,
        tools=tools,
        timeout=min(timeout, 300),
    )

    # Persist to case if requested
    if case_id and ioc_id:
        for r in results:
            try:
                db.save_pivot_result(
                    ioc_id=int(ioc_id),
                    tool_id=r.get("tool", "unknown"),
                    tool_name=r.get("tool_name", ""),
                    result=r,
                )
            except Exception:
                pass

    return jsonify({
        "ioc_type": ioc_type,
        "value": value,
        "results": results,
    })


@app.route("/pivot/stream", methods=["GET"])
def pivot_stream():
    """
    SSE endpoint — streams tool output line-by-line as tools run.

    Query params: ioc_type, value, tools (comma-sep), timeout, case_id, ioc_id
    """
    ioc_type = request.args.get("ioc_type", "").strip().lower()
    value = request.args.get("value", "").strip()
    tools_str = request.args.get("tools", "")
    tools = [t.strip() for t in tools_str.split(",") if t.strip()] if tools_str else None
    timeout = int(request.args.get("timeout", 60))
    case_id = request.args.get("case_id")
    ioc_id = request.args.get("ioc_id")

    if not ioc_type or not value:
        def _err():
            yield f"event: error\ndata: {json.dumps({'error': 'ioc_type and value required'})}\n\n"
        return Response(stream_with_context(_err()), mimetype="text/event-stream")

    def _generate():
        for chunk in stream_pivot(
            ioc_type=ioc_type,
            value=value,
            tools=tools,
            timeout=min(timeout, 300),
        ):
            # Persist pivot result events to case
            if case_id and ioc_id and chunk.startswith("event: result"):
                try:
                    data_line = chunk.split("\ndata: ", 1)[1].rstrip("\n")
                    result = json.loads(data_line)
                    db.save_pivot_result(
                        ioc_id=int(ioc_id),
                        tool_id=result.get("tool", ""),
                        tool_name=result.get("tool_name", ""),
                        result=result,
                    )
                except Exception:
                    pass
            yield chunk

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/pivot/tools", methods=["GET"])
def pivot_tools():
    """Return the IOC→tool mapping so the UI can show defaults."""
    return jsonify(IOC_TOOL_MAP)


# ═══════════════════════════════════════════════════════════════════════════
# Case Management (NEW in v2.0)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/cases", methods=["GET"])
def list_cases():
    status = request.args.get("status")
    return jsonify(db.list_cases(status))


@app.route("/cases", methods=["POST"])
def create_case():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    try:
        case = db.create_case(name, body.get("description", ""))
        return jsonify(case), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 409


@app.route("/cases/<int:case_id>", methods=["GET"])
def get_case(case_id):
    case = db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    case["stats"] = db.get_case_stats(case_id)
    return jsonify(case)


@app.route("/cases/<int:case_id>", methods=["PUT"])
def update_case(case_id):
    body = request.get_json(silent=True) or {}
    case = db.update_case(case_id, **body)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(case)


@app.route("/cases/<int:case_id>", methods=["DELETE"])
def delete_case(case_id):
    if db.delete_case(case_id):
        return jsonify({"deleted": True})
    return jsonify({"error": "Case not found"}), 404


@app.route("/cases/<int:case_id>/files", methods=["POST"])
def add_case_file(case_id):
    """Upload a file, analyze it, and add the result to the case."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], f"case{case_id}_{filename}")
    try:
        file.save(filepath)
        analysis = analyze_file(filepath)
        report_md = generate_humanized_report(analysis)
        report_html = markdown.markdown(report_md, extensions=["tables", "fenced_code"])
        analysis["report_html"] = report_html

        case_file = db.add_file_to_case(case_id, analysis)
        return jsonify(case_file), 201
    except Exception as e:
        return jsonify({"error": f"Failed to add file: {str(e)}"}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route("/cases/<int:case_id>/files", methods=["GET"])
def list_case_files(case_id):
    return jsonify(db.list_case_files(case_id))


@app.route("/cases/<int:case_id>/files/<int:file_id>", methods=["GET"])
def get_case_file(case_id, file_id):
    f = db.get_case_file(file_id)
    if not f or f["case_id"] != case_id:
        return jsonify({"error": "Not found"}), 404
    return jsonify(f)


@app.route("/cases/<int:case_id>/iocs", methods=["GET"])
def list_case_iocs(case_id):
    ioc_type = request.args.get("type")
    return jsonify(db.list_case_iocs(case_id, ioc_type))


@app.route("/cases/<int:case_id>/iocs", methods=["POST"])
def add_case_ioc(case_id):
    body = request.get_json(silent=True) or {}
    ioc_type = body.get("ioc_type", "").strip()
    value = body.get("value", "").strip()
    if not ioc_type or not value:
        return jsonify({"error": "ioc_type and value required"}), 400
    ioc = db.add_ioc(case_id, ioc_type, value,
                     file_id=body.get("file_id"),
                     context=body.get("context", ""))
    if not ioc:
        return jsonify({"error": "IOC already exists in this case"}), 409
    return jsonify(ioc), 201


@app.route("/cases/<int:case_id>/pivot-results", methods=["GET"])
def list_case_pivot_results(case_id):
    iocs = db.list_case_iocs(case_id)
    all_results = []
    for ioc in iocs:
        pivot_results = db.list_ioc_pivot_results(ioc["id"])
        for pr in pivot_results:
            pr["ioc_type"] = ioc["ioc_type"]
            pr["ioc_value"] = ioc["value"]
            all_results.append(pr)
    all_results.sort(key=lambda x: x.get("ran_at", ""), reverse=True)
    return jsonify(all_results)


@app.route("/cases/<int:case_id>/notes", methods=["GET"])
def list_case_notes(case_id):
    return jsonify(db.list_case_notes(case_id))


@app.route("/cases/<int:case_id>/notes", methods=["POST"])
def add_case_note(case_id):
    body = request.get_json(silent=True) or {}
    content = (body.get("content") or "").strip()
    if not content:
        return jsonify({"error": "content is required"}), 400
    note = db.add_note(case_id, content)
    return jsonify(note), 201


@app.route("/cases/<int:case_id>/timeline", methods=["GET"])
def case_timeline(case_id):
    return jsonify(db.get_case_timeline(case_id))


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _generate_comparison_narrative(comparison: dict) -> str:
    files = comparison["files"]
    filenames = [f["filename"] for f in files]

    report = (
        f"## Comparison Summary\n\nAnalyzed **{len(files)} files**: "
        f"{', '.join(filenames)}.\n\n"
    )

    rel = comparison.get("relationship_assessment", "UNRELATED")
    rel_map = {
        "DUPLICATE_FILES": "Some files are **byte-for-byte duplicates** — identical SHA-256 hashes.",
        "RELATED_FILES": "These files appear **related** — shared embedded artifacts suggest common origin.",
        "SAME_TYPE": "All files share the **same type** but no other forensic indicators.",
        "UNRELATED": "Files appear **forensically unrelated** across all indicators analyzed.",
    }
    report += rel_map.get(rel, "") + "\n\n"

    report += "## Risk Ranking\n\n"
    for r in comparison["risk_comparison"]:
        icon = {"CRITICAL": "🔴", "SUSPICIOUS": "🟠", "CAUTION": "🟡", "CLEAN": "🟢"}.get(
            r["label"], "⚪"
        )
        report += f"- {icon} **{r['filename']}** — {r['score']}/100 ({r['label']})\n"

    if comparison.get("findings"):
        report += "\n## Key Findings\n\n"
        for f in comparison["findings"]:
            icon = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(f["severity"], "⚪")
            report += f"{icon} **{f['title']}:** {f['detail']}\n\n"

    shared = comparison.get("shared_artifacts", {})
    if shared.get("has_shared"):
        report += "## Shared Artifacts\n\n"
        for kind, label in [
            ("shared_urls", "URLs"),
            ("shared_emails", "Emails"),
            ("shared_ips", "IPs"),
            ("shared_domains", "Domains"),
        ]:
            items = shared.get(kind, {})
            if items:
                report += f"**{label} in multiple files:**\n"
                for val, fnames in items.items():
                    report += f"- `{val}` → {', '.join(fnames)}\n"
                report += "\n"

    report += "## Entropy Comparison\n\n"
    for e in comparison["entropy_comparison"]:
        report += f"- **{e['filename']}** — {e['entropy']:.4f} ({e['assessment']})\n"

    return report


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
