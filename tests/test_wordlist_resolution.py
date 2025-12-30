from pathlib import Path

import pytest
from fastapi import HTTPException

from app.core.path_utils import resolve_wordlist_path


def test_resolve_wordlist_prefers_data_dir(tmp_path):
    data_dir = tmp_path / "app" / "data"
    data_dir.mkdir(parents=True)
    wordlist = data_dir / "paths.txt"
    wordlist.write_text("/admin\n/api\n")

    search_roots = [
        data_dir,
        tmp_path / "app",
        tmp_path / "app" / "app" / "data",
        tmp_path,
    ]

    resolved = resolve_wordlist_path("paths.txt", search_roots=search_roots)

    assert resolved == wordlist


def test_resolve_wordlist_raises_with_candidates(tmp_path):
    search_roots = [
        tmp_path / "app" / "data",
        tmp_path / "app",
        tmp_path / "app" / "app" / "data",
        tmp_path,
    ]

    with pytest.raises(HTTPException) as exc:
        resolve_wordlist_path("missing.txt", search_roots=search_roots)

    assert exc.value.status_code == 422
    assert "missing.txt" in exc.value.detail
    for expected in search_roots:
        assert str(expected) in exc.value.detail
