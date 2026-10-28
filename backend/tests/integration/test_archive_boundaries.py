"""Reject unsafe entry writes, including Windows device/ADS and noncanonical names."""

import zipfile
import pytest
from arena.verifier.archive import ArchiveSecurityError, safe_extract_archive


@pytest.mark.parametrize(
    "name",
    ["NUL", "artifacts/CON.txt", "artifacts/value.bin:stream", "artifacts/unsafe?.bin"],
)
def test_windows_unsafe_archive_names_are_rejected(tmp_path, name):
    source = tmp_path / "untrusted.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr(name, b"synthetic fixture")
    with pytest.raises(ArchiveSecurityError):
        safe_extract_archive(source, tmp_path / "destination")
