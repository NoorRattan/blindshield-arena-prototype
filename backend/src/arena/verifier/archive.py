"""Safe zip archive validation and extraction with zip-bomb and traversal protection."""

from __future__ import annotations

from pathlib import Path
from pathlib import PurePosixPath
from typing import List
import zipfile


class ArchiveSecurityError(ValueError):
    """Raised when an archive violates safety constraints (zip-bomb, traversal, symlink)."""


MAX_TOTAL_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_FILES_COUNT = 10_000
MAX_COMPRESSION_RATIO = 100.0  # Max expansion ratio


def safe_extract_archive(archive_path: Path, destination_dir: Path) -> List[Path]:
    """Extract zip archive safely into destination directory.

    Enforces strict path containment, no symlinks, max file counts,
    and uncompressed size caps to neutralize zip-bomb attacks.
    """
    archive_path = archive_path.resolve()
    destination_dir = destination_dir.resolve()
    destination_dir.mkdir(parents=True, exist_ok=True)
    if archive_path.stat().st_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise ArchiveSecurityError("Compressed archive exceeds input byte bound")

    if not zipfile.is_zipfile(archive_path):
        raise ArchiveSecurityError(f"File is not a valid zip archive: {archive_path}")

    extracted_files: List[Path] = []
    total_uncompressed_bytes = 0
    normalized_names: set[str] = set()

    with zipfile.ZipFile(archive_path, "r") as zf:
        infolist = zf.infolist()
        if len(infolist) > MAX_FILES_COUNT:
            raise ArchiveSecurityError(
                f"Archive exceeds maximum file count: {len(infolist)} > {MAX_FILES_COUNT}"
            )

        for info in infolist:
            # 1. Path traversal and absolute path protection
            filename = info.filename
            if not filename.isascii():
                raise ArchiveSecurityError(
                    "Evidence entry names must be canonical ASCII"
                )
            if (
                not filename
                or "\\" in filename
                or "\x00" in filename
                or ":" in filename
            ):
                raise ArchiveSecurityError(f"Invalid archive entry name: {filename!r}")
            if (
                filename.startswith("/")
                or filename.startswith("\\")
                or (len(filename) > 1 and filename[1] == ":")
            ):
                raise ArchiveSecurityError(
                    f"Absolute path in archive rejected: {filename}"
                )

            # ZIP names use POSIX separators on every host. Case-fold as well so
            # archives cannot overwrite the same destination on Windows.
            zip_path = PurePosixPath(filename)
            normalized_parts = zip_path.parts
            normalized_name = "/".join(normalized_parts).casefold()
            raw_parts = filename.rstrip("/").split("/")
            reserved = {"con", "prn", "aux", "nul", "conin$", "conout$"} | {
                f"{prefix}{index}"
                for prefix in ("com", "lpt")
                for index in range(1, 10)
            }
            if any(
                part.split(".", 1)[0].casefold() in reserved
                or any(char in '<>:"|?*' or ord(char) < 32 for char in part)
                for part in raw_parts
            ):
                raise ArchiveSecurityError("Unsafe cross-platform archive entry")
            if (
                not normalized_parts
                or any(
                    part in ("", ".", "..") or part.endswith((".", " "))
                    for part in raw_parts
                )
                or normalized_name in normalized_names
            ):
                raise ArchiveSecurityError(
                    f"Unsafe or duplicate archive entry: {filename}"
                )
            normalized_names.add(normalized_name)

            target_path = (destination_dir / Path(*normalized_parts)).resolve()
            if not target_path.is_relative_to(destination_dir):
                raise ArchiveSecurityError(
                    f"Extracted path escapes destination directory: {filename}"
                )

            # 2. Check for symlinks in zip metadata (external_attr unix bits)
            unix_mode = info.external_attr >> 16
            file_type = unix_mode & 0o170000
            if file_type == 0o120000:
                raise ArchiveSecurityError(
                    f"Symlinks in evidence archives are strictly forbidden: {filename}"
                )
            if file_type not in (0, 0o100000, 0o040000):
                raise ArchiveSecurityError(
                    f"Special files in evidence archives are forbidden: {filename}"
                )

            # 3. Uncompressed size and compression ratio protection
            total_uncompressed_bytes += info.file_size
            if total_uncompressed_bytes > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ArchiveSecurityError(
                    f"Archive exceeds uncompressed size cap of {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
                )

            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_COMPRESSION_RATIO and info.file_size > 1_000_000:
                    raise ArchiveSecurityError(
                        f"Zip bomb detected: compression ratio {ratio:.1f} exceeds limit {MAX_COMPRESSION_RATIO}"
                    )

            if info.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
            else:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target_path, "wb") as dst:
                    # Stream chunks safely
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        dst.write(chunk)
                extracted_files.append(target_path)

    return extracted_files
