#!/usr/bin/env python3
"""Topic maintenance worker.

Periodically reconciles the topic graph against the ground truth in
meta_server.chunks. Three passes per cycle:

  1. recompute_centroids: replace each topic's centroid, chunk_count,
     and doc_count with values derived from its current chunks. Fixes
     the drift that accumulates when documents are re-indexed (old
     chunks are deleted but their contributions are still folded into
     the running-mean centroid). Topics with zero chunks afterwards are
     deleted (CASCADE removes their edges).

  2. merge_duplicate_topics: for each topic, find its top-K nearest
     centroids; any pair above MERGE_THRESHOLD cosine similarity is
     unioned. Each union-find class collapses to its highest-chunk-count
     topic; chunks and edges from the losers are redirected, then the
     losers are deleted. Centroids for the survivors are recomputed.

  3. recompute_similar_edges: drop all `similar` edges and rebuild from
     each topic's top-K nearest centroids above SIMILAR_MIN_WEIGHT. This
     populates the "web" view that retrieval can walk.

CLI:
  python -m indexer.topic_maintenance --once       # single pass, exit
  python -m indexer.topic_maintenance --loop       # daemon (default)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Dict, List, Tuple

from sqlalchemy import select, text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from MyLogger import Logger
from common.db import SCHEMA, Topic, make_engine, make_session_factory

log = Logger(log_name="topic_maintenance", log_level=logging.DEBUG).get_logger()


MAINTENANCE_INTERVAL = int(os.getenv("MAINTENANCE_INTERVAL", "3600"))
MERGE_THRESHOLD = float(os.getenv("MERGE_THRESHOLD", "0.95"))
MERGE_NEAREST_K = int(os.getenv("MERGE_NEAREST_K", "20"))
SIMILAR_TOP_K = int(os.getenv("SIMILAR_TOP_K", "10"))
SIMILAR_MIN_WEIGHT = float(os.getenv("SIMILAR_MIN_WEIGHT", "0.7"))


# ---------------------------------------------------------------------------
# Pass 1: centroid recomputation
# ---------------------------------------------------------------------------

def recompute_centroids(session) -> Tuple[int, int]:
    """Returns (topics_updated, topics_deleted)."""
    update_sql = text(
        f"""
        UPDATE {SCHEMA}.topics t
        SET centroid = sub.avg_emb,
            chunk_count = sub.cnt,
            doc_count = sub.doc_cnt,
            updated_at = now()
        FROM (
            SELECT topic_id,
                   avg(embedding) AS avg_emb,
                   count(*) AS cnt,
                   count(DISTINCT document_id) AS doc_cnt
            FROM {SCHEMA}.chunks
            WHERE topic_id IS NOT NULL
            GROUP BY topic_id
        ) sub
        WHERE t.id = sub.topic_id
        """
    )
    result = session.execute(update_sql)
    updated = result.rowcount or 0

    # Topics with zero chunks (after the update they'd still show whatever
    # chunk_count they had before; reset those to zero, then delete).
    session.execute(
        text(
            f"""
            UPDATE {SCHEMA}.topics
            SET chunk_count = 0, doc_count = 0, centroid = NULL, updated_at = now()
            WHERE id NOT IN (
                SELECT DISTINCT topic_id FROM {SCHEMA}.chunks WHERE topic_id IS NOT NULL
            )
              AND (chunk_count > 0 OR centroid IS NOT NULL)
            """
        )
    )
    delete_result = session.execute(
        text(f"DELETE FROM {SCHEMA}.topics WHERE chunk_count = 0 AND centroid IS NULL")
    )
    deleted = delete_result.rowcount or 0
    session.commit()
    return updated, deleted


# ---------------------------------------------------------------------------
# Pass 2: duplicate merging
# ---------------------------------------------------------------------------

class _UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[int, int] = {}

    def find(self, x: int) -> int:
        while self.parent.setdefault(x, x) != x:
            self.parent[x] = self.parent.setdefault(self.parent[x], self.parent[x])
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def merge_duplicate_topics(
    session,
    threshold: float = MERGE_THRESHOLD,
    nearest_k: int = MERGE_NEAREST_K,
) -> int:
    """Union-find collapse of near-duplicate topics. Returns merges performed."""
    rows = session.execute(
        select(Topic.id).where(Topic.centroid.is_not(None)).order_by(Topic.id)
    ).all()
    topic_ids = [r.id for r in rows]
    if len(topic_ids) < 2:
        return 0

    uf = _UnionFind()
    for tid in topic_ids:
        ref = session.get(Topic, tid)
        if ref is None or ref.centroid is None:
            continue
        nearest = session.execute(
            select(
                Topic.id,
                (1.0 - Topic.centroid.cosine_distance(ref.centroid)).label("sim"),
            )
            .where(Topic.id != tid)
            .where(Topic.centroid.is_not(None))
            .order_by(Topic.centroid.cosine_distance(ref.centroid))
            .limit(nearest_k)
        ).all()
        for n in nearest:
            if float(n.sim) >= threshold:
                uf.union(tid, n.id)

    # Group ids by their root in the union-find.
    groups: Dict[int, List[int]] = {}
    for tid in topic_ids:
        groups.setdefault(uf.find(tid), []).append(tid)

    merges = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        topics = session.execute(select(Topic).where(Topic.id.in_(members))).scalars().all()
        keeper = max(topics, key=lambda t: (int(t.chunk_count or 0), -t.id))
        for t in topics:
            if t.id == keeper.id:
                continue
            _merge_topic_into(session, keep_id=keeper.id, drop_id=t.id)
            merges += 1
    if merges:
        session.commit()
        # Centroids for the survivors changed; refresh in a fresh pass so the
        # similar-edge computation below uses correct vectors.
        recompute_centroids(session)
    return merges


def _merge_topic_into(session, *, keep_id: int, drop_id: int) -> None:
    log.info("merging topic %d into %d", drop_id, keep_id)
    params = {"keep": keep_id, "drop": drop_id}
    # 1. Move chunks.
    session.execute(
        text(f"UPDATE {SCHEMA}.chunks SET topic_id = :keep WHERE topic_id = :drop"),
        params,
    )
    # 2. Outgoing edges from drop -> redirect to keep, sum weights.
    session.execute(
        text(
            f"""
            INSERT INTO {SCHEMA}.topic_edges (src_topic_id, dst_topic_id, kind, weight, updated_at)
            SELECT :keep, dst_topic_id, kind, weight, now()
            FROM {SCHEMA}.topic_edges
            WHERE src_topic_id = :drop AND dst_topic_id != :keep
            ON CONFLICT (src_topic_id, dst_topic_id, kind) DO UPDATE
            SET weight = {SCHEMA}.topic_edges.weight + EXCLUDED.weight,
                updated_at = now()
            """
        ),
        params,
    )
    # 3. Incoming edges to drop -> redirect to keep, sum weights.
    session.execute(
        text(
            f"""
            INSERT INTO {SCHEMA}.topic_edges (src_topic_id, dst_topic_id, kind, weight, updated_at)
            SELECT src_topic_id, :keep, kind, weight, now()
            FROM {SCHEMA}.topic_edges
            WHERE dst_topic_id = :drop AND src_topic_id != :keep
            ON CONFLICT (src_topic_id, dst_topic_id, kind) DO UPDATE
            SET weight = {SCHEMA}.topic_edges.weight + EXCLUDED.weight,
                updated_at = now()
            """
        ),
        params,
    )
    # 4. Drop the loser; CASCADE removes any remaining edge rows.
    session.execute(text(f"DELETE FROM {SCHEMA}.topics WHERE id = :drop"), params)


# ---------------------------------------------------------------------------
# Pass 3: similar edges
# ---------------------------------------------------------------------------

def recompute_similar_edges(
    session,
    top_k: int = SIMILAR_TOP_K,
    min_weight: float = SIMILAR_MIN_WEIGHT,
) -> int:
    """Returns the number of `similar` edge rows written."""
    session.execute(
        text(f"DELETE FROM {SCHEMA}.topic_edges WHERE kind = 'similar'")
    )
    result = session.execute(
        text(
            f"""
            INSERT INTO {SCHEMA}.topic_edges (src_topic_id, dst_topic_id, kind, weight, updated_at)
            SELECT src.id, near.id, 'similar', near.sim, now()
            FROM {SCHEMA}.topics src
            CROSS JOIN LATERAL (
                SELECT t.id, 1.0 - (t.centroid <=> src.centroid) AS sim
                FROM {SCHEMA}.topics t
                WHERE t.id <> src.id AND t.centroid IS NOT NULL
                ORDER BY t.centroid <=> src.centroid
                LIMIT :top_k
            ) near
            WHERE src.centroid IS NOT NULL AND near.sim >= :min_weight
            ON CONFLICT (src_topic_id, dst_topic_id, kind) DO UPDATE
            SET weight = EXCLUDED.weight, updated_at = now()
            """
        ),
        {"top_k": top_k, "min_weight": min_weight},
    )
    inserted = result.rowcount or 0
    session.commit()
    return inserted


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_cycle(session_factory) -> None:
    log.info("Topic maintenance cycle starting")
    started = time.time()

    with session_factory() as session:
        updated, deleted = recompute_centroids(session)
        log.info("centroids: updated=%d deleted_orphans=%d", updated, deleted)

    with session_factory() as session:
        merges = merge_duplicate_topics(session)
        log.info("duplicate merges: %d", merges)

    with session_factory() as session:
        edges = recompute_similar_edges(session)
        log.info("similar edges written: %d", edges)

    log.info("Topic maintenance cycle complete in %.1fs", time.time() - started)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="run a single cycle and exit")
    parser.add_argument(
        "--interval",
        type=int,
        default=MAINTENANCE_INTERVAL,
        help="seconds between cycles in daemon mode",
    )
    args = parser.parse_args()

    session_factory = make_session_factory(make_engine())

    if args.once:
        run_cycle(session_factory)
        return

    log.info("Topic maintenance daemon: interval=%ds", args.interval)
    try:
        while True:
            try:
                run_cycle(session_factory)
            except Exception as exc:
                log.exception("Cycle failed: %s", exc)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("Topic maintenance daemon stopped")


if __name__ == "__main__":
    main()
