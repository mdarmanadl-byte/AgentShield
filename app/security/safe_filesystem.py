
"""Workspace-confined, bounded filesystem reads.

POSIX:
    Uses descriptor-relative opens with O_NOFOLLOW for every component.

Windows:
    Opens the final object with CreateFileW and OPEN_REPARSE_POINT,
    rejects reparse points, and verifies the final path obtained from
    the opened handle. Intermediate components are checked before opening.

Security note:
    The Windows implementation verifies the final opened object's location,
    but intermediate path checks are not atomic. Use OS-level isolation and
    restrictive workspace ACLs when an adversary can concurrently modify
    workspace directories.
"""

import os
import stat
from pathlib import Path


class UnsafePathError(ValueError):
    """The requested path is invalid or outside the workspace."""


class SafeWorkspace:
    MAX_READ_BYTES = 64_000
    READ_CHUNK_BYTES = 8_192

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("Workspace root must be a directory.")

    def _validate_relative_path(self, relative_path: str) -> tuple[str, ...]:
        if not isinstance(relative_path, str) or not relative_path.strip():
            raise UnsafePathError("A non-empty relative path is required.")

        if "\x00" in relative_path or "\\" in relative_path:
            raise UnsafePathError("Invalid path characters.")

        supplied = Path(relative_path)

        if supplied.is_absolute() or ".." in supplied.parts:
            raise UnsafePathError(
                "Absolute paths and path traversal are prohibited."
            )

        if not supplied.parts or any(
            part in {"", "."} for part in supplied.parts
        ):
            raise UnsafePathError("Invalid relative path.")

        # Reject drive-like and alternate-stream syntax.
        if any(":" in part for part in supplied.parts):
            raise UnsafePathError("Drive and alternate-stream paths are prohibited.")

        return supplied.parts

    def read_text(self, relative_path: str) -> str:
        """Read a bounded UTF-8 regular file without intentionally following links."""
        parts = self._validate_relative_path(relative_path)

        if os.name == "posix":
            return self._read_posix(parts)

        if os.name == "nt":
            return self._read_windows(parts)

        raise NotImplementedError(
            "Safe filesystem access is not implemented on this platform."
        )

    def _decode(self, content: bytes) -> str:
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UnsafePathError("File is not valid UTF-8 text.") from exc

    def _read_posix(self, parts: tuple[str, ...]) -> str:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory_flag = getattr(os, "O_DIRECTORY", None)

        if nofollow is None or directory_flag is None:
            raise NotImplementedError(
                "This POSIX platform lacks required no-follow open flags."
            )

        root_fd = os.open(
            self.root,
            os.O_RDONLY | directory_flag | nofollow,
        )
        current_fd = root_fd
        file_fd = None

        try:
            for component in parts[:-1]:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | directory_flag | nofollow,
                    dir_fd=current_fd,
                )

                if current_fd != root_fd:
                    os.close(current_fd)

                current_fd = next_fd

            file_fd = os.open(
                parts[-1],
                os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
                dir_fd=current_fd,
            )

            metadata = os.fstat(file_fd)

            if not stat.S_ISREG(metadata.st_mode):
                raise UnsafePathError("Only regular files can be read.")

            if metadata.st_size > self.MAX_READ_BYTES:
                raise UnsafePathError("File exceeds the read-size limit.")

            chunks: list[bytes] = []
            total = 0

            while True:
                chunk = os.read(
                    file_fd,
                    min(
                        self.READ_CHUNK_BYTES,
                        self.MAX_READ_BYTES + 1 - total,
                    ),
                )

                if not chunk:
                    break

                chunks.append(chunk)
                total += len(chunk)

                if total > self.MAX_READ_BYTES:
                    raise UnsafePathError("File exceeds the read-size limit.")

            return self._decode(b"".join(chunks))

        except OSError as exc:
            if exc.errno in {getattr(os, "ELOOP", -1)}:
                raise UnsafePathError(
                    "Symbolic links are prohibited."
                ) from exc
            raise

        finally:
            if file_fd is not None:
                os.close(file_fd)

            if current_fd != root_fd:
                os.close(current_fd)

            os.close(root_fd)

    def _read_windows(self, parts: tuple[str, ...]) -> str:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x00000080
        FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
        FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
        FILE_ATTRIBUTE_DIRECTORY = 0x00000010
        FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
        FILE_TYPE_DISK = 0x0001
        FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        class FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
            _fields_ = [
                ("FileAttributes", wintypes.DWORD),
                ("ReparseTag", wintypes.DWORD),
            ]

        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE

        kernel32.GetFileInformationByHandleEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL

        kernel32.GetFinalPathNameByHandleW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD

        kernel32.GetFileType.argtypes = [wintypes.HANDLE]
        kernel32.GetFileType.restype = wintypes.DWORD

        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        def win_error(message: str) -> OSError:
            return ctypes.WinError(ctypes.get_last_error(), message)

        def final_path(handle) -> str:
            size = 512

            while size <= 32_768:
                buffer = ctypes.create_unicode_buffer(size)
                length = kernel32.GetFinalPathNameByHandleW(
                    handle, buffer, size, 0
                )

                if length == 0:
                    raise win_error("Could not resolve opened file handle.")

                if length < size:
                    result = buffer.value

                    if result.startswith("\\\\?\\UNC\\"):
                        result = "\\\\" + result[8:]
                    elif result.startswith("\\\\?\\"):
                        result = result[4:]

                    return os.path.normcase(os.path.abspath(result))

                size = length + 1

            raise UnsafePathError("Resolved path is too long.")

        def open_handle(path: Path):
            handle = kernel32.CreateFileW(
                str(path),
                GENERIC_READ,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL
                | FILE_FLAG_OPEN_REPARSE_POINT
                | FILE_FLAG_SEQUENTIAL_SCAN,
                None,
            )

            if handle == INVALID_HANDLE_VALUE:
                raise win_error("Could not open filesystem object.")

            return handle

        def attributes(handle) -> FILE_ATTRIBUTE_TAG_INFO:
            info = FILE_ATTRIBUTE_TAG_INFO()

            if not kernel32.GetFileInformationByHandleEx(
                handle,
                FILE_ATTRIBUTE_TAG_INFO_CLASS,
                ctypes.byref(info),
                ctypes.sizeof(info),
            ):
                raise win_error("Could not inspect opened filesystem object.")

            return info

        def is_within_root(candidate: str, root: str) -> bool:
            try:
                return os.path.commonpath([candidate, root]) == root
            except ValueError:
                return False

        root_path = os.path.normcase(os.path.abspath(str(self.root)))
        current_path = self.root

        # Reject links/reparse points in intermediate components before
        # opening the final path. Final-handle verification follows below.
        for component in parts[:-1]:
            current_path = current_path / component

            try:
                info = current_path.lstat()
            except OSError:
                raise

            if stat.S_ISLNK(info.st_mode):
                raise UnsafePathError("Symbolic links are prohibited.")

            if getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
                raise UnsafePathError("Reparse points are prohibited.")

            if not stat.S_ISDIR(info.st_mode):
                raise UnsafePathError("A path component is not a directory.")

        target = self.root.joinpath(*parts)
        handle = open_handle(target)
        fd = None

        try:
            info = attributes(handle)

            if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
                raise UnsafePathError("Reparse points are prohibited.")

            if info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY:
                raise UnsafePathError("Only regular files can be read.")

            if kernel32.GetFileType(handle) != FILE_TYPE_DISK:
                raise UnsafePathError("Only disk files can be read.")

            actual_path = final_path(handle)

            if not is_within_root(actual_path, root_path):
                raise UnsafePathError("Resolved file is outside the workspace.")

            # Transfer handle ownership to a Python file descriptor.
            fd = msvcrt.open_osfhandle(
                int(handle),
                os.O_RDONLY | getattr(os, "O_BINARY", 0),
            )
            handle = None

            chunks: list[bytes] = []
            total = 0

            while True:
                chunk = os.read(
                    fd,
                    min(
                        self.READ_CHUNK_BYTES,
                        self.MAX_READ_BYTES + 1 - total,
                    ),
                )

                if not chunk:
                    break

                chunks.append(chunk)
                total += len(chunk)

                if total > self.MAX_READ_BYTES:
                    raise UnsafePathError("File exceeds the read-size limit.")

            return self._decode(b"".join(chunks))

        finally:
            if fd is not None:
                os.close(fd)

            if handle is not None:
                kernel32.CloseHandle(handle)
