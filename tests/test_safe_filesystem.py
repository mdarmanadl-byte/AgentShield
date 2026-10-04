
"""Regression tests for SafeWorkspace filesystem access."""

import os
from pathlib import Path

import pytest

from app.security.safe_filesystem import SafeWorkspace, UnsafePathError


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "hello.txt").write_text("hello world", encoding="utf-8")
    (root / "nested").mkdir()
    (root / "nested" / "notes.txt").write_text(
        "nested content", encoding="utf-8"
    )
    return root


def test_reads_regular_file(workspace: Path) -> None:
    safe = SafeWorkspace(workspace)
    assert safe.read_text("hello.txt") == "hello world"


def test_reads_nested_file(workspace: Path) -> None:
    safe = SafeWorkspace(workspace)
    assert safe.read_text("nested/notes.txt") == "nested content"


@pytest.mark.parametrize(
    "path",
    [
        "",
        "../outside.txt",
        "/etc/passwd",
        "nested/../../outside.txt",
        ".",
    ],
)
def test_rejects_unsafe_paths(workspace: Path, path: str) -> None:
    safe = SafeWorkspace(workspace)

    with pytest.raises(UnsafePathError):
        safe._validate_relative_path(path)


def test_rejects_backslash_paths(workspace: Path) -> None:
    safe = SafeWorkspace(workspace)

    with pytest.raises(UnsafePathError):
        safe._validate_relative_path(r"nested\notes.txt")


def test_rejects_symlink_to_outside_file(
    workspace: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    link = workspace / "outside-link.txt"

    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlink creation unavailable: {exc}")

    safe = SafeWorkspace(workspace)

    if os.name != "posix":
        with pytest.raises(NotImplementedError):
            safe.read_text("outside-link.txt")
    else:
        with pytest.raises((OSError, UnsafePathError)):
            safe.read_text("outside-link.txt")


def test_rejects_symlinked_intermediate_directory(
    workspace: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "external"
    outside.mkdir()
    (outside / "secret.txt").write_text("private", encoding="utf-8")

    link = workspace / "external-link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlink creation unavailable: {exc}")

    safe = SafeWorkspace(workspace)

    if os.name != "posix":
        with pytest.raises(NotImplementedError):
            safe.read_text("external-link/secret.txt")
    else:
        with pytest.raises((OSError, UnsafePathError)):
            safe.read_text("external-link/secret.txt")


def test_rejects_directory_as_file(workspace: Path) -> None:
    safe = SafeWorkspace(workspace)

    if os.name != "posix":
        with pytest.raises(NotImplementedError):
            safe.read_text("nested")
    else:
        with pytest.raises((OSError, UnsafePathError)):
            safe.read_text("nested")


def test_rejects_file_over_size_limit(workspace: Path) -> None:
    oversized = workspace / "oversized.txt"
    oversized.write_bytes(b"x" * (SafeWorkspace.MAX_READ_BYTES + 1))
    safe = SafeWorkspace(workspace)

    if os.name != "posix":
        with pytest.raises(NotImplementedError):
            safe.read_text("oversized.txt")
    else:
        with pytest.raises(UnsafePathError, match="size"):
            safe.read_text("oversized.txt")


def test_rejects_invalid_utf8(workspace: Path) -> None:
    (workspace / "invalid.txt").write_bytes(b"\xff\xfe\xfa")
    safe = SafeWorkspace(workspace)

    if os.name != "posix":
        with pytest.raises(NotImplementedError):
            safe.read_text("invalid.txt")
    else:
        with pytest.raises(UnsafePathError, match="UTF-8"):
            safe.read_text("invalid.txt")


def test_rejects_nonexistent_workspace(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        SafeWorkspace(tmp_path / "missing")
