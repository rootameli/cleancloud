"""Shared filesystem utilities for resolving scan resources."""

from pathlib import Path
from typing import Iterable, List, Optional

from fastapi import HTTPException
import structlog

logger = structlog.get_logger()

# Default search roots are ordered to reflect the container layout first
# while keeping local development paths as fallbacks.
DEFAULT_WORDLIST_ROOTS: List[Path] = [
    Path("/app/data"),
    Path("/app"),
    Path("/app/app/data"),
    Path(__file__).resolve().parents[2] / "data",
    Path.cwd(),
]


def resolve_wordlist_path(
    wordlist: str, search_roots: Optional[Iterable[Path]] = None
) -> Path:
    """Resolve a wordlist path deterministically.

    Resolution order (for relative paths):
    1. /app/data/<wordlist>
    2. /app/<wordlist>
    3. /app/app/data/<wordlist>
    4. <project_root>/data/<wordlist>
    5. <cwd>/<wordlist>

    Args:
        wordlist: Absolute or relative wordlist path provided by the user.
        search_roots: Optional custom search roots used primarily for testing.

    Raises:
        HTTPException: 422 when the wordlist cannot be resolved.
    """

    candidates: List[str] = []
    wordlist_path = Path(wordlist)

    if wordlist_path.is_absolute():
        candidates.append(str(wordlist_path))
        if wordlist_path.exists():
            logger.info(
                "Resolved wordlist path",
                wordlist=wordlist,
                resolved=str(wordlist_path),
                candidates=candidates,
            )
            return wordlist_path

        logger.warning(
            "Wordlist resolution failed",
            wordlist=wordlist,
            candidates=candidates,
        )
        raise HTTPException(
            status_code=422,
            detail=f"Wordlist not found: {wordlist}. Tried: {', '.join(candidates)}",
        )

    roots = list(search_roots) if search_roots is not None else DEFAULT_WORDLIST_ROOTS
    for root in roots:
        candidate = (root / wordlist_path).resolve()
        candidates.append(str(candidate))
        if candidate.exists():
            logger.info(
                "Resolved wordlist path",
                wordlist=wordlist,
                resolved=str(candidate),
                candidates=candidates,
            )
            return candidate

    logger.warning(
        "Wordlist resolution failed",
        wordlist=wordlist,
        candidates=candidates,
    )
    raise HTTPException(
        status_code=422,
        detail=f"Wordlist not found: {wordlist}. Tried: {', '.join(candidates)}",
    )
