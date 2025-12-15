"""Module runner for orchestrating external modules."""

import asyncio
import os
import uuid
import time
from pathlib import Path
from typing import Any, Dict, List

from fastapi import HTTPException
import structlog

from .database import EventDB, get_async_session
from .modules_registry import get_module

logger = structlog.get_logger()


async def _persist_event(
    scan_id: str | None,
    level: str,
    message: str,
    module_id: str | None = None,
) -> None:
    """Persist a log event to the database."""

    session_factory = get_async_session()
    async with session_factory() as session:
        event = EventDB(
            scan_id=uuid.UUID(scan_id) if scan_id else None,
            event_type="log",
            data={"level": level, "message": message, "module_id": module_id},
        )
        session.add(event)
        await session.commit()


async def _stream_output(pipe: asyncio.StreamReader, level: str, scan_id: str, module_id: str):
    while True:
        line = await pipe.readline()
        if not line:
            break
        message = line.decode().rstrip()
        await _persist_event(scan_id, level, message, module_id)


async def run_module(
    scan_id: str,
    module_id: str,
    targets: List[str],
    settings: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Run a declared module and stream logs to the database."""

    settings = settings or {}
    if os.getenv("LAB_MODE") != "1":
        raise HTTPException(status_code=403, detail="Module execution disabled outside LAB_MODE")

    module_def = get_module(module_id)
    if not module_def:
        raise HTTPException(status_code=404, detail=f"Unknown module {module_id}")

    work_base = Path("data/scans") / scan_id / module_def.id
    work_base.mkdir(parents=True, exist_ok=True)

    targets_file = work_base / "targets.txt"
    targets_file.write_text("\n".join(targets))

    env = os.environ.copy()
    env.update({
        "TARGETS_FILE": str(targets_file),
        "SCAN_ID": scan_id,
    })
    env.update({k: str(v) for k, v in settings.items()})

    await _persist_event(scan_id, "info", f"Starting module {module_def.display_name}", module_id)

    start_time = time.monotonic()
    process = await asyncio.create_subprocess_exec(
        *module_def.entrypoint,
        cwd=str(module_def.working_dir),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout_task = asyncio.create_task(_stream_output(process.stdout, "info", scan_id, module_id))
    stderr_task = asyncio.create_task(_stream_output(process.stderr, "error", scan_id, module_id))

    try:
        await asyncio.wait_for(process.wait(), timeout=module_def.timeout)
    except asyncio.TimeoutError:
        process.kill()
        await _persist_event(scan_id, "error", f"Module {module_id} timed out", module_id)
        raise HTTPException(status_code=504, detail=f"Module {module_id} execution timed out")
    finally:
        await stdout_task
        await stderr_task

    duration = time.monotonic() - start_time

    output_paths = {
        name: str(Path(module_def.working_dir) / relative)
        for name, relative in module_def.output_paths.items()
    }

    await _persist_event(
        scan_id,
        "info",
        f"Module {module_def.display_name} finished with code {process.returncode}",
        module_id,
    )

    return {
        "returncode": process.returncode,
        "duration": duration,
        "output_paths": output_paths,
    }


async def persist_log_event(scan_id: str | None, message: str, level: str = "info", module_id: str | None = None):
    """Public helper for persisting log events from other components."""

    await _persist_event(scan_id, level, message, module_id)
