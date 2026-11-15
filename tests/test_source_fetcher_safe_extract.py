import io
import os
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mcpsec.static.source_fetcher import _fetch_npm


def _extract_archive(archive_path: Path, dest_dir: Path) -> None:
    """Extraction helper mimicking source_fetcher extraction."""
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(path=dest_dir, filter="data")


def test_malicious_tarball_does_not_escape_extraction_dir():
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        tar_path = td_path / "malicious.tar.gz"

        with tarfile.open(tar_path, "w:gz") as tar:
            # Normal member
            normal_data = b"normal content"
            normal_info = tarfile.TarInfo(name="package/normal.txt")
            normal_info.size = len(normal_data)
            tar.addfile(normal_info, io.BytesIO(normal_data))

            # Traversing member
            evil_data = b"evil content"
            evil_info = tarfile.TarInfo(name="../escaped.txt")
            evil_info.size = len(evil_data)
            tar.addfile(evil_info, io.BytesIO(evil_data))

        extract_dir = td_path / "extract"
        extract_dir.mkdir()

        escaped_file = td_path / "escaped.txt"

        try:
            _extract_archive(tar_path, extract_dir)
        except Exception:
            # Raising (e.g. tarfile.OutsideDestinationError) is acceptable
            pass

        assert not escaped_file.exists()


def test_clean_tarball_extracts_all_members():
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        tar_path = td_path / "clean.tar.gz"

        with tarfile.open(tar_path, "w:gz") as tar:
            f1_data = b"hello world"
            f1_info = tarfile.TarInfo(name="package/index.js")
            f1_info.size = len(f1_data)
            tar.addfile(f1_info, io.BytesIO(f1_data))

            f2_data = b"{\"name\": \"pkg\"}"
            f2_info = tarfile.TarInfo(name="package/package.json")
            f2_info.size = len(f2_data)
            tar.addfile(f2_info, io.BytesIO(f2_data))

        extract_dir = td_path / "extract"
        extract_dir.mkdir()

        _extract_archive(tar_path, extract_dir)

        assert (extract_dir / "package" / "index.js").exists()
        assert (extract_dir / "package" / "index.js").read_bytes() == b"hello world"
        assert (extract_dir / "package" / "package.json").exists()


@pytest.mark.asyncio
async def test_fetch_npm_uses_filter_data(tmp_path):
    # Create malicious tarball
    tar_path = tmp_path / "testpkg-1.0.0.tgz"
    with tarfile.open(tar_path, "w:gz") as tar:
        evil_data = b"evil"
        evil_info = tarfile.TarInfo(name="../escaped_npm.txt")
        evil_info.size = len(evil_data)
        tar.addfile(evil_info, io.BytesIO(evil_data))

    async def fake_proc(*args, **kwargs):
        cwd = kwargs.get("cwd")
        if cwd:
            # Copy malicious tarball into npm temp_dir
            target = Path(cwd) / "testpkg-1.0.0.tgz"
            target.write_bytes(tar_path.read_bytes())
        mock = AsyncMock()
        mock.communicate.return_value = (b"testpkg-1.0.0.tgz\n", b"")
        return mock

    parent_escaped = tmp_path.parent / "escaped_npm.txt"

    with patch("shutil.which", return_value="npm"), \
         patch("asyncio.create_subprocess_exec", side_effect=fake_proc):
        res = await _fetch_npm("testpkg")
        assert res is None  # Caught and returned None
        assert not parent_escaped.exists()
