"""Shared prompt builder + JSON parser for the combined extraction call.

The combined call asks the LLM for category, keywords, summary, AND a list
of topic spans in a single response. All providers share this prompt and
parser; only the transport (chat completion call) differs per provider.
"""

import json
import logging
import re
from typing import List, Optional

from .base import LLMResponse, TopicCandidate, TopicSpan

log = logging.getLogger(__name__)


SYSTEM_PROMPT = (
    "You are a document analysis assistant that builds a topic graph. "
    "For each document you analyze, you produce a strict JSON object with "
    "category, keywords, summary, and a list of topics found in the text. "
    "Prefer assigning to existing topics over creating new ones. "
    "Output only the JSON object, no prose."
)


def build_combined_prompt(
    content: str,
    candidate_topics: Optional[List[TopicCandidate]] = None,
    language: str = "en",
    file_path: Optional[str] = None,
    max_topics: int = 8,
) -> str:
    candidate_topics = candidate_topics or []
    candidate_block = (
        "\n".join(
            f"- {t.name}" + (f": {t.description}" if t.description else "")
            for t in candidate_topics
        )
        if candidate_topics
        else "(none yet - propose new topics as needed)"
    )

    file_line = f"File: {file_path}\n" if file_path else ""
    return f"""{file_line}Language: {language}

Existing topic candidates (prefer these names when applicable):
{candidate_block}

Document content:
\"\"\"
{content}
\"\"\"

Return a JSON object with this exact shape:
{{
  "category": "<short single-word or short-phrase document type>",
  "keywords": "<comma-separated list of 5-10 keywords>",
  "summary": "<2-3 sentence summary>",
  "topics": [
    {{
      "name": "<topic name; reuse one from the candidates if it fits>",
      "description": "<one-sentence description of the topic in this doc>",
      "aspect": "<one of: definition | method | result | context | example | other>",
      "span_text": "<verbatim quoted passage from the document>",
      "char_start": <integer offset into the document content, or null>,
      "char_end": <integer offset into the document content, or null>
    }}
  ]
}}

Return at most {max_topics} topics. If a topic clearly maps to an existing
candidate, use that exact name. Only propose a new topic name when no
candidate fits."""


_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def parse_combined_response(text: str) -> LLMResponse:
    """Parse the JSON envelope. Tolerant of markdown fences and leading prose."""
    json_blob = _extract_json(text)
    try:
        data = json.loads(json_blob)
    except json.JSONDecodeError as exc:
        log.warning("Failed to parse combined extraction JSON: %s", exc)
        return LLMResponse(raw_response=text)

    topics = []
    for raw in data.get("topics") or []:
        if not isinstance(raw, dict):
            continue
        name = (raw.get("name") or "").strip()
        if not name:
            continue
        topics.append(
            TopicSpan(
                name=name,
                description=(raw.get("description") or "").strip(),
                span_text=(raw.get("span_text") or "").strip(),
                aspect=(raw.get("aspect") or None),
                char_start=_coerce_int(raw.get("char_start")),
                char_end=_coerce_int(raw.get("char_end")),
            )
        )

    return LLMResponse(
        category=(data.get("category") or None),
        keywords=(data.get("keywords") or None),
        summary=(data.get("summary") or None),
        topics=topics,
        raw_response=text,
    )


def _extract_json(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        # Strip ```json ... ``` fences
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    match = _JSON_BLOCK_RE.search(text)
    return match.group(0) if match else text


def _coerce_int(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
