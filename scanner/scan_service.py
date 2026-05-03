#!/usr/bin/env python3
"""Filesystem scanner - Postgres-backed.

Walks SCAN_DIRECTORY periodically and enqueues files into
meta_server.index_queue for the index worker to process. A file is
enqueued when:
  - it has no row in meta_server.documents yet, OR
  - the file's mtime is newer than documents.modification_date, OR
  - documents.summary or documents.inferred_category is missing
    (previous indexing failed midway).

Already-pending queue rows are skipped to avoid duplicates.
"""

import logging
import os
import sys
import time
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from MyLogger import Logger
from common.db import Document, IndexQueueItem, make_engine, make_session_factory

log = Logger(log_name="scan_service", log_level=logging.DEBUG).get_logger()


SCAN_DIRECTORY = os.getenv("SCAN_DIRECTORY", "/data")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "60"))


def is_stale(file_path: str, doc: Document) -> Tuple[bool, str]:
    try:
        disk_mtime = os.path.getmtime(file_path)
    except FileNotFoundError:
        return False, "File no longer exists"

    if disk_mtime > (doc.modification_date or 0):
        return True, "Modified since last index"
    if not doc.inferred_category:
        return True, "Missing inferred_category"
    if not doc.summary:
        return True, "Missing summary"
    return False, ""


def scan_and_queue(session, directory: str) -> None:
    log.info("Starting scan cycle for %s", directory)
    queued = 0
    for subdir, _, files in os.walk(directory):
        for filename in files:
            if filename.startswith("."):
                continue
            file_path = os.path.abspath(os.path.join(subdir, filename))
            if os.path.islink(file_path):
                continue
            try:
                os.path.getmtime(file_path)
            except FileNotFoundError:
                log.warning("Skipped (file vanished): %s", file_path)
                continue

            existing = session.execute(
                select(Document).where(Document.path == file_path)
            ).scalar_one_or_none()

            if existing is None:
                reason: Optional[str] = "Not indexed yet"
            else:
                stale, reason_or_empty = is_stale(file_path, existing)
                reason = reason_or_empty if stale else None

            if reason is None:
                continue

            stmt = (
                pg_insert(IndexQueueItem.__table__)
                .values(
                    file_path=file_path,
                    status="pending",
                    added_at=time.time(),
                )
                .on_conflict_do_nothing(index_elements=["file_path"])
            )
            try:
                result = session.execute(stmt)
                session.commit()
                if result.rowcount:
                    queued += 1
                    log.info("Queued: %s (%s)", file_path, reason)
            except SQLAlchemyError as exc:
                session.rollback()
                log.warning("Queue insert failed for %s: %s", file_path, exc)

    log.info("Scan cycle complete: queued %d new files", queued)


def run_scan_service(directory: str, interval: int) -> None:
    engine = make_engine()
    session_factory = make_session_factory(engine)
    log.info("Watching directory: %s (interval=%ds)", directory, interval)

    try:
        while True:
            with session_factory() as session:
                scan_and_queue(session, directory)
            time.sleep(interval)
    except KeyboardInterrupt:
        log.info("Scan service terminated by user.")
    except Exception as exc:
        log.exception("Fatal error in scan service: %s", exc)


if __name__ == "__main__":
    run_scan_service(SCAN_DIRECTORY, SCAN_INTERVAL)
