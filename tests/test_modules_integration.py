import asyncio
import os
from pathlib import Path
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.core.modules_registry import get_module, MODULES_REGISTRY, ModuleDefinition
from app.core.module_runner import run_module
from app.core.database import (
    init_database,
    cleanup_database,
    get_async_session,
    ScanDB,
    EventDB,
    FindingDB,
)
from app.api.endpoints_enhanced import get_scan_logs
from app.api.websocket_enhanced import get_dashboard_stats
from app.core.result_parsers.leancloud_js import parse_leancloud_js


@pytest.fixture()
def setup_db(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path/'test.db'}"
    asyncio.run(init_database(db_url))
    yield get_async_session()
    asyncio.run(cleanup_database())


def test_registry_contains_module():
    module = get_module("leancloud_js")
    assert module is not None
    assert "modules_leancloud" in str(module.working_dir)


def test_runner_persists_events_and_paths(monkeypatch, setup_db, tmp_path):
    session_factory = setup_db
    os.environ["LAB_MODE"] = "1"

    test_module_id = "echo_test"
    (tmp_path / "main.go").write_text("package main\nfunc main() {}")
    MODULES_REGISTRY[test_module_id] = ModuleDefinition(
        id=test_module_id,
        display_name="Echo Test",
        type="subprocess",
        working_dir=tmp_path,
        entrypoint=[
            "python",
            "-c",
            "print('hello'); import sys; print('oops', file=sys.stderr)",
        ],
        timeout=5,
        output_paths={"result_dir": "ResultJS"},
    )

    scan_uuid = uuid.uuid4()

    async def _prepare():
        async with session_factory() as session:
            scan = ScanDB(
                id=scan_uuid,
                crack_id="test-crack",
                status="queued",
                created_at=datetime.now(timezone.utc),
                targets=["http://example.com"],
                wordlist="paths.txt",
                modules=[],
                concurrency=10,
                rate_limit=10,
                timeout=10,
                follow_redirects=True,
                regex_rules=[],
                path_rules=[],
                total_urls=1,
            )
            session.add(scan)
            await session.commit()

    asyncio.run(_prepare())
    result = asyncio.run(run_module(str(scan_uuid), test_module_id, ["http://example.com"], {}))

    async def _fetch():
        async with session_factory() as session:
            return (
                await session.execute(select(EventDB).where(EventDB.scan_id == scan_uuid))
            ).scalars().all()

    events = asyncio.run(_fetch())
    assert events, "Runner should persist events"
    assert Path(result["output_paths"]["result_dir"]).exists()

    MODULES_REGISTRY.pop(test_module_id, None)


def test_logs_endpoint_returns_events(setup_db):
    session_factory = setup_db
    scan_uuid = uuid.uuid4()

    async def _prepare_and_call():
        async with session_factory() as session:
            scan = ScanDB(
                id=scan_uuid,
                crack_id="test-crack",
                status="queued",
                created_at=datetime.now(timezone.utc),
                targets=["http://example.com"],
                wordlist="paths.txt",
                modules=[],
                concurrency=10,
                rate_limit=10,
                timeout=10,
                follow_redirects=True,
                regex_rules=[],
                path_rules=[],
                total_urls=1,
            )
            session.add(scan)
            session.add(
                EventDB(
                    scan_id=scan_uuid,
                    event_type="log",
                    data={"level": "info", "message": "hello"},
                    created_at=datetime.now(timezone.utc),
                )
            )
            await session.commit()

            return await get_scan_logs(str(scan_uuid), tail=10, session=session)

    response = asyncio.run(_prepare_and_call())

    assert response["total_logs"] == 1
    assert response["logs"][0]["message"] == "hello"


def test_dashboard_stats_reflect_db(setup_db):
    session_factory = setup_db
    scan_uuid = uuid.uuid4()

    async def _prepare():
        async with session_factory() as session:
            scan = ScanDB(
                id=scan_uuid,
                crack_id="test-crack",
                status="running",
                created_at=datetime.now(timezone.utc),
                targets=["http://example.com"],
                wordlist="paths.txt",
                modules=[],
                concurrency=10,
                rate_limit=10,
                timeout=10,
                follow_redirects=True,
                regex_rules=[],
                path_rules=[],
                total_urls=2,
                processed_urls=1,
            )
            session.add(scan)
            session.add(
                FindingDB(
                    id=uuid.uuid4(),
                    scan_id=scan_uuid,
                    crack_id="test-crack",
                    service="aws",
                    pattern_id="demo",
                    url="http://example.com",
                    source_url="http://example.com",
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    evidence="key",
                    evidence_masked="key",
                    works=False,
                    confidence=0.5,
                    severity="medium",
                )
            )
            session.add(
                EventDB(
                    scan_id=scan_uuid,
                    event_type="log",
                    data={"level": "info", "message": "hello"},
                    created_at=datetime.now(timezone.utc),
                )
            )
            await session.commit()

    asyncio.run(_prepare())
    stats = asyncio.run(get_dashboard_stats())
    assert stats["provider_hits"]["aws"] == 1
    assert stats["total_findings"] == 1
    assert stats["events"] >= 1
    assert stats["active_scans"] >= 1
    assert stats["processed_urls"] == 1
    assert stats["total_urls"] == 2
    assert stats["progress_percent"] > 0


def test_parser_creates_findings_from_multiple_files(tmp_path, setup_db):
    session_factory = setup_db
    result_dir = tmp_path / "ResultJS"
    result_dir.mkdir()
    (result_dir / "dir_keys.txt").write_text("http://example.com:secret\n")
    (result_dir / "aws_valid.txt").write_text("AKIA....\n")
    (result_dir / "env_keys.txt").write_text("ENV_VAR=value\n")

    scan_uuid = uuid.uuid4()

    async def _prepare():
        async with session_factory() as session:
            scan = ScanDB(
                id=scan_uuid,
                crack_id="crack",
                status="queued",
                created_at=datetime.now(timezone.utc),
                targets=["http://example.com"],
                wordlist="paths.txt",
                modules=[],
                concurrency=10,
                rate_limit=10,
                timeout=10,
                follow_redirects=True,
                regex_rules=[],
                path_rules=[],
                total_urls=1,
            )
            session.add(scan)
            await session.commit()

    asyncio.run(_prepare())
    findings = asyncio.run(
        parse_leancloud_js(str(scan_uuid), "leancloud_js", {"result_dir": str(result_dir)})
    )

    async def _fetch():
        async with session_factory() as session:
            return (await session.execute(select(FindingDB))).scalars().all()

    stored = asyncio.run(_fetch())

    assert len(findings) == 3
    assert len(stored) == 3
    assert any(f.service == "aws" for f in stored)
    assert any("env" in f.pattern_id for f in stored)
