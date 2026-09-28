from __future__ import annotations

import os
from typing import Dict, Optional, Tuple


# Maximum number of bytes we ever read from a file. Every signature in the
# table is shorter than this; the limit exists so a caller cannot accidentally
# trigger a multi-gigabyte read on a hostile path.
_MAX_READ = 512


class MagicNumberError(ValueError):
    """Raised when a file's leading bytes match no known signature."""


# Each entry is (offset, magic_bytes, label). The offset lets us express
# formats whose marker is not at byte zero — e.g. ELF's ``\x7fELF`` is at the
# start, but a CD sector header would sit further in. Keeping the offset
# explicit in the table is clearer than burying it in a lambda.
_signatures: Dict[str, Tuple[int, bytes]] = {}


def register(name: str, magic: bytes, offset: int = 0) -> None:
    """Register a signature under ``name``.

    Re-registering an existing name replaces it; this keeps the table
    deterministic if a caller wants to override a built-in.
    """
    if not isinstance(magic, (bytes, bytearray)):
        raise TypeError("magic must be bytes")
    if offset < 0:
        raise ValueError("offset must be non-negative")
    _signatures[name] = (offset, bytes(magic))


def _builtins() -> None:
    # Populated lazily so the module can be imported before the table is
    # touched — handy for tests that want a clean slate.
    if _signatures:
        return
    register("pdf", b"%PDF")
    register("png", b"\x89PNG\r\n\x1a\n")
    register("gif87a", b"GIF87a")
    register("gif89a", b"GIF89a")
    register("zip", b"PK\x03\x04")
    # An empty archive and a spanned archive share the PK prefix but differ at
    # byte 2; both are listed so the longer match wins.
    register("zip_empty", b"PK\x05\x06")
    register("zip_spanned", b"PK\x07\x08")
    register("gzip", b"\x1f\x8b")
    register("elf", b"\x7fELF")
    register("macho_32", b"\xfe\xed\xfa\xce")
    register("macho_64", b"\xfe\xed\xfa\xcf")
    register("macho_universal", b"\xca\xfe\xba\xbe")
    register("class", b"\xca\xfe\xba\xbe")  # same magic; resolved by caller
    register("rar14", b"RE~^\x00")
    register("rar5", b"Rar!\x1a\x07\x01\x00")
    register("rar", b"Rar!\x1a\x07\x00")
    register("bmp", b"BM")
    register("webp", b"RIFF", 0)  # WebP is RIFF....WEBP; we only check RIFF.
    register("wav", b"RIFF")
    register("avi", b"RIFF")
    register("ico", b"\x00\x00\x01\x00")
    register("cur", b"\x00\x00\x02\x00")
    register("tar", b"ustar", 257)
    register("xml", b"<?xml")
    register("flac", b"fLaC")
    register("mp3_id3", b"ID3")
    register("ogg", b"OggS")
    register("psd", b"8BPS")
    register("sqlite", b"SQLite format 3\x00")


def signatures() -> Dict[str, Tuple[int, bytes]]:
    """Return a copy of the current signature table."""
    _builtins()
    return dict(_signatures)


def _match(head: bytes) -> Optional[str]:
    best: Optional[str] = None
    best_len = -1
    for name, (offset, magic) in _signatures.items():
        end = offset + len(magic)
        if end > len(head):
            continue
        if head[offset:end] == magic:
            # When two signatures share a prefix (e.g. RIFF for WAV and AVI,
            # or PK for the three ZIP variants), prefer the longer, more
            # specific match.
            if len(magic) > best_len:
                best = name
                best_len = len(magic)
    return best


def sniff_bytes(data: bytes) -> str:
    """Identify ``data`` by its leading bytes.

    Raises :class:`MagicNumberError` if no signature matches. The input need
    not be a full file; pass at least ``_MAX_READ`` bytes for best results.
    """
    _builtins()
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    found = _match(bytes(data))
    if found is None:
        raise MagicNumberError("no matching signature")
    return found


def sniff(path: str) -> str:
    """Read the head of ``path`` and return its identified type.

    Only the first ``_MAX_READ`` bytes are read, so this is safe to call on
    large files. Raises :class:`MagicNumberError` on no match and
    :class:`OSError` / :class:`ValueError` from the underlying ``open`` for
    missing or unreadable paths.
    """
    _builtins()
    with open(path, "rb") as fh:
        head = fh.read(_MAX_READ)
    return sniff_bytes(head)
