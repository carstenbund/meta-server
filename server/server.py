"""HTTP server: file browser + topic-graph retrieval API.

DB writes are owned by the indexer/scanner; this server is read-mostly.
Retrieval endpoints (/search/semantic, /topics/<id>/neighbors, /ask)
live in routes_retrieval and call the transport-agnostic
RetrievalService in common.retrieval, so the same logic is reusable
from MCP / inference_server hooks later.
"""

import logging
import os
import sys

from flask import (
    Flask,
    abort,
    g,
    jsonify,
    render_template,
    request,
    send_from_directory,
)
from flask_cors import CORS
from sqlalchemy import func, select

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from MyLogger import Logger
from common.db import Document, make_engine, make_session_factory
from common.retrieval import RetrievalService  # noqa: F401  (kept for direct import use)
from llm_providers import get_llm_provider
from llm_providers.embeddings import build_registry
from llm_providers.factory import ProviderConfig
from server.routes_retrieval import make_retrieval_blueprint


log = Logger(log_name="mserver", log_level=logging.DEBUG).get_logger()


BASE_DIR = os.environ.get("BASE_DIR", "/data")
STATIC_DIR = os.environ.get("STATIC_DIR", "/app/static")
THUMBNAILS_DIR = os.environ.get(
    "THUMBNAILS_DIR", "/var/server/data/meta-server/thumbnails"
)


# ---------- shared singletons --------------------------------------------------

engine = make_engine()
SessionFactory = make_session_factory(engine)
embedders = build_registry()


def _llm_factory():
    return get_llm_provider(provider_name=os.getenv("LLM_PROVIDER"), config=ProviderConfig())


# ---------- Flask app ----------------------------------------------------------

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)
app.register_blueprint(make_retrieval_blueprint(SessionFactory, embedders, _llm_factory))


@app.before_request
def before_request():
    g.endpoint = request.endpoint
    g.full_path = request.full_path


@app.errorhandler(404)
def page_not_found(_):
    log.info(
        "404 at %s ip=%s endpoint=%s full_path=%s",
        request.url,
        request.remote_addr,
        getattr(g, "endpoint", "?"),
        getattr(g, "full_path", "?"),
    )
    return "<h2>Page not found</h2>", 404


# ---------- file browser -------------------------------------------------------

def _doc_to_metadata(doc: Document) -> dict:
    return {
        "id": doc.id,
        "path": doc.path,
        "size": doc.size,
        "modification_date": doc.modification_date,
        "category": doc.category,
        "inferred_category": doc.inferred_category,
        "keywords": doc.keywords,
        "summary": doc.summary,
        "file_type": doc.file_type,
        "creator_software": doc.creator_software,
        "origin_date": doc.origin_date,
        "pe_info": doc.pe_info,
    }


@app.route("/files", methods=["GET"])
def list_files():
    relative_directory = request.args.get("directory", "/")
    directory = os.path.join(BASE_DIR, relative_directory.lstrip("/"))
    if not os.path.isdir(directory):
        return jsonify([])

    results = []
    with SessionFactory() as session:
        for entry in os.scandir(directory):
            if entry.name.startswith("."):
                continue
            file_path = os.path.join(directory, entry.name)
            relative_path = os.path.relpath(file_path, BASE_DIR)

            if entry.is_dir():
                # Aggregate from documents whose path starts with this directory.
                prefix = file_path.rstrip("/") + "/"
                file_count = session.execute(
                    select(func.count(Document.id)).where(Document.path.like(prefix + "%"))
                ).scalar_one()
                total_size = session.execute(
                    select(func.coalesce(func.sum(Document.size), 0)).where(
                        Document.path.like(prefix + "%")
                    )
                ).scalar_one()
                results.append({
                    "path": relative_path,
                    "is_directory": True,
                    "id": None,
                    "metadata": {
                        "path": relative_path,
                        "size": int(total_size or 0),
                        "modification_date": entry.stat().st_mtime,
                        "file_count": int(file_count or 0),
                    },
                })
            else:
                doc = session.execute(
                    select(Document).where(Document.path == file_path)
                ).scalar_one_or_none()
                meta = _doc_to_metadata(doc) if doc else {
                    "path": relative_path,
                    "size": entry.stat().st_size,
                    "modification_date": entry.stat().st_mtime,
                }
                results.append({
                    "path": relative_path,
                    "is_directory": False,
                    "id": entry.name,
                    "metadata": meta,
                })

    results.sort(key=lambda x: (not x["is_directory"], x["path"].lower()))
    return jsonify(results)


@app.route("/files/<path:file_id>", methods=["GET"])
def get_file(file_id):
    file_path = os.path.join(BASE_DIR, file_id.lstrip("/"))
    with SessionFactory() as session:
        doc = session.execute(
            select(Document).where(Document.path == file_path)
        ).scalar_one_or_none()
        if doc is None:
            log.info("/files/ not found: %s", file_path)
            return jsonify({"error": "File not found"}), 404
        return jsonify({
            "metadata": _doc_to_metadata(doc),
            "content": doc.summary,  # full text now lives in chunks
        })


# ---------- static / preview / template routes (unchanged) --------------------

@app.route("/")
def serve_html():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/translate", methods=["POST"])
def translate():
    data = request.json or {}
    text = data.get("text")
    target_lang = data.get("target_lang", "ja")
    return jsonify({"translated_text": f"Translated to {target_lang}: {text}"})


@app.route("/thumbnails/<path:filename>")
def serve_thumbnail(filename):
    prefix = "win95/mcrlnsalg/"
    if filename.startswith(prefix):
        filename = filename[len(prefix):]

    base_name, _ = os.path.splitext(filename)
    candidates = [
        (base_name + ".webp", "image/webp"),
        (base_name + ".png", "image/png"),
        (base_name + ".jpg", "image/jpeg"),
    ]
    for name, mimetype in candidates:
        path = os.path.join(THUMBNAILS_DIR, name)
        if os.path.exists(path):
            return send_from_directory(
                os.path.dirname(path), os.path.basename(path), mimetype=mimetype
            )
    abort(404)


@app.route("/doc_preview/<path:filename>")
def preview(filename):
    lower = filename.lower()
    if lower.endswith(".pdf"):
        return render_template("pdf_preview.html", file_url=f"/preview/{filename}")
    if lower.endswith(".docx") or lower.endswith(".doc"):
        return render_template("doc_preview.html", file_url=f"/preview/{filename}")
    if lower.endswith(".xlsx") or lower.endswith(".xls"):
        return render_template("excel_preview.html", file_url=f"/preview/{filename}")
    if lower.endswith(".csv"):
        return render_template("csv_preview.html", file_url=f"/preview/{filename}")
    return "File type not supported", 400


@app.route("/preview/<path:file_path>", methods=["GET", "HEAD"])
def preview_file(file_path):
    file_dir, file_name = os.path.split(file_path)
    abs_dir = os.path.join(BASE_DIR, file_dir)
    full = os.path.join(abs_dir, file_name)
    if os.path.exists(full):
        return send_from_directory(abs_dir, file_name)
    log.error("preview file not found: %s", full)
    abort(404, description="File not found")


@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory(STATIC_DIR, filename)


if __name__ == "__main__":
    web_ip = os.environ.get("WEB_IP", "0.0.0.0")
    web_port = int(os.environ.get("WEB_PORT", "5000"))
    log.debug("port=%d host=%s", web_port, web_ip)
    app.run(port=web_port, host=web_ip, debug=True, use_reloader=False)
