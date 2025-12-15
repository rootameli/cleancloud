"""Parser for LeanCloud JS module outputs."""

import uuid
from pathlib import Path
from typing import Dict, List
from datetime import datetime, timezone

import structlog

from ..database import get_async_session, ScanDB, FindingDB
from ..module_runner import persist_log_event

logger = structlog.get_logger()


async def parse_leancloud_js(scan_id: str, module_id: str, output_paths: Dict[str, str]) -> List[FindingDB]:
    """Parse output files from LeanCloud JS module and persist findings."""

    result_dir = Path(output_paths.get("result_dir", ""))
    if not result_dir.exists():
        await persist_log_event(scan_id, f"Result directory not found for {module_id}", "warning", module_id)
        return []

    session_factory = get_async_session()
    findings: List[FindingDB] = []

    async with session_factory() as session:
        scan_db = await session.get(ScanDB, uuid.UUID(scan_id))
        if not scan_db:
            await persist_log_event(scan_id, "Scan not found for parser", "error", module_id)
            return []

        for file_name in ["dir_keys.txt", "env_keys.txt", "twilio_credentials.txt"]:
            file_path = result_dir / file_name
            if not file_path.exists():
                continue

            for line in file_path.read_text().splitlines():
                if ":" not in line:
                    continue
                url, evidence = line.rsplit(":", 1)
                finding = FindingDB(
                    scan_id=scan_db.id,
                    crack_id=scan_db.crack_id,
                    service="generic",
                    pattern_id=file_name,
                    url=url,
                    source_url=url,
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    evidence=evidence,
                    evidence_masked=evidence,
                    works=False,
                    confidence=0.5,
                    severity="medium",
                )
                findings.append(finding)

        session.add_all(findings)
        await session.commit()

    await persist_log_event(scan_id, f"Parsed {len(findings)} findings from {module_id}", "info", module_id)
    return findings
