"""HTTP transport adapter for the RetrievalService.

This is one of multiple planned consumer adapters: HTTP (here), MCP
(separate module), inference_server chat hook (separate module). All
three call into common.retrieval.RetrievalService; the only thing that
differs is request/response framing.
"""

from __future__ import annotations

import logging
from typing import Optional

from flask import Blueprint, jsonify, request

from common.retrieval import RetrievalService, SearchFilters

log = logging.getLogger(__name__)


def make_retrieval_blueprint(session_factory, embedders, llm_factory):
    """Build the blueprint.

    session_factory: callable returning a SQLAlchemy session.
    embedders:       EmbedderRegistry (built once, shared).
    llm_factory:     callable returning a BaseLLMProvider, used by /ask.
                     Pulled lazily so /search/semantic doesn't require an
                     LLM provider to be configured.
    """
    bp = Blueprint("retrieval", __name__)

    def _filters_from_payload(payload: dict) -> Optional[SearchFilters]:
        raw = payload.get("filters") or {}
        if not raw:
            return None
        return SearchFilters(
            file_type=raw.get("file_type"),
            inferred_category=raw.get("inferred_category"),
            category=raw.get("category"),
            topic_ids=raw.get("topic_ids"),
        )

    @bp.route("/search/semantic", methods=["POST"])
    def search_semantic():
        payload = request.get_json(silent=True) or {}
        query = (payload.get("query") or "").strip()
        if not query:
            return jsonify({"error": "query is required"}), 400
        top_k = int(payload.get("top_k", 10))
        filters = _filters_from_payload(payload)
        with session_factory() as session:
            service = RetrievalService(session, embedders)
            hits = service.search_chunks(query, top_k=top_k, filters=filters)
        return jsonify({"hits": [h.to_dict() for h in hits]})

    @bp.route("/topics/<int:topic_id>/neighbors", methods=["GET"])
    def topic_neighbors(topic_id: int):
        kinds_arg = request.args.getlist("kind") or None
        limit = int(request.args.get("limit", 20))
        with session_factory() as session:
            service = RetrievalService(session, embedders)
            neighbors = service.topic_neighbors(topic_id, kinds=kinds_arg, limit=limit)
        return jsonify({"topic_id": topic_id, "neighbors": [n.to_dict() for n in neighbors]})

    @bp.route("/ask", methods=["POST"])
    def ask():
        payload = request.get_json(silent=True) or {}
        query = (payload.get("query") or "").strip()
        if not query:
            return jsonify({"error": "query is required"}), 400
        top_k = int(payload.get("top_k", 5))
        filters = _filters_from_payload(payload)
        try:
            llm = llm_factory()
        except Exception as exc:
            log.error("LLM provider unavailable: %s", exc)
            return jsonify({"error": "no LLM provider configured"}), 503
        with session_factory() as session:
            service = RetrievalService(session, embedders, llm=llm)
            result = service.ask(query, top_k=top_k, filters=filters)
        return jsonify(result.to_dict())

    return bp
