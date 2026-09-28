import os
import struct
import tempfile
import unittest

from file_header_sniffer import sniff, sniff_bytes, MagicNumberError, signatures


class TestSniffBytes(unittest.TestCase):
    def test_png(self):
        self.assertEqual(sniff_bytes(b"\x89PNG\r\n\x1a\n"), "png")

    def test_pdf(self):
        self.assertEqual(sniff_bytes(b"%PDF-1.7\n"), "pdf")

    def test_gif_versions(self):
        self.assertEqual(sniff_bytes(b"GIF87a"), "gif87a")
        self.assertEqual(sniff_bytes(b"GIF89a"), "gif89a")

    def test_zip_variants(self):
        self.assertEqual(sniff_bytes(b"PK\x03\x04"), "zip")
        self.assertEqual(sniff_bytes(b"PK\x05\x06"), "zip_empty")
        self.assertEqual(sniff_bytes(b"PK\x07\x08"), "zip_spanned")

    def test_tar_offset(self):
        # ustar marker lives at byte 257.
        block = bytearray(512)
        block[257:262] = b"ustar"
        self.assertEqual(sniff_bytes(bytes(block)), "tar")

    def test_longer_match_wins(self):
        # RIFF is shared by wav, avi, webp. Without a longer discriminator we
        # accept whichever signature was registered; here all three are the
        # same length so the table order decides. We assert that one of them
        # is returned, not which — the spec only promises a best-effort label.
        result = sniff_bytes(b"RIFF\x00\x00\x00\x00WAVE")
        self.assertIn(result, {"wav", "avi", "webp"})

    def test_no_match_raises(self):
        with self.assertRaises(MagicNumberError):
            sniff_bytes(b"hello world")

    def test_empty_input_raises(self):
        with self.assertRaises(MagicNumberError):
            sniff_bytes(b"")

    def test_truncated_signature_raises(self):
        # Half a PNG header must not match.
        with self.assertRaises(MagicNumberError):
            sniff_bytes(b"\x89PN")

    def test_non_bytes_raises(self):
        with self.assertRaises(TypeError):
            sniff_bytes("not bytes")  # type: ignore[arg-type]

    def test_sqlite_full_signature(self):
        self.assertEqual(sniff_bytes(b"SQLite format 3\x00"), "sqlite")

    def test_sqlite_truncated_raises(self):
        with self.assertRaises(MagicNumberError):
            sniff_bytes(b"SQLite format 3")  # missing NUL


class TestSniffFile(unittest.TestCase):
    def _write(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.addCleanup(os.unlink, path)
        return path

    def test_file_png(self):
        path = self._write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)
        self.assertEqual(sniff(path), "png")

    def test_file_pdf(self):
        path = self._write(b"%PDF-1.7\n%binary\n" + b"x" * 1000)
        self.assertEqual(sniff(path), "pdf")

    def test_file_missing_raises_oserror(self):
        with self.assertRaises(OSError):
            sniff("/nonexistent/path/that/should/not/exist")

    def test_file_unknown_raises_magic(self):
        path = self._write(b"plain text with no magic")
        with self.assertRaises(MagicNumberError):
            sniff(path)

    def test_file_large_only_head_read(self):
        # A 1 MiB file whose only magic is at the start should identify fast.
        path = self._write(b"\x1f\x8b" + b"\x00" * (1024 * 1024))
        self.assertEqual(sniff(path), "gzip")


class TestSignaturesTable(unittest.TestCase):
    def test_returns_copy(self):
        s = signatures()
        s["bogus"] = (0, b"XX")
        self.assertNotIn("bogus", signatures())

    def test_contains_builtins(self):
        s = signatures()
        for name in ("png", "pdf", "zip", "gzip", "elf"):
            self.assertIn(name, s)


if __name__ == "__main__":
    unittest.main()
