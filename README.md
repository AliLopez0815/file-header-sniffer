# File Header Sniffer

Reads the first 512 bytes of a file and identifies its type by magic-number signature. Standard library only; no dependencies.

## Usage

```python
from file_header_sniffer import sniff, sniff_bytes, MagicNumberError

try:
    kind = sniff_bytes(b"\x89PNG\r\n\x1a\n")  # -> "png"
except MagicNumberError:
    print("unknown type")

kind = sniff_bytes(b"%PDF-1.7\n")      # -> "pdf"
```

`sniff(path)` reads at most 512 bytes from disk and returns a label string. `sniff_bytes(data)` does the same on an in-memory buffer. Both raise `MagicNumberError` when nothing matches.

## Why

Trust `Content-Type` from uploads and you will eventually store a `.exe` labelled `image/png`. Checking the leading bytes is cheaper than fully parsing the file and catches the common lie. This library trades breadth for simplicity: around thirty common formats, no C extensions, no pip install. If you need to identify 700 formats, use `libmagic`.

## Edge cases

- **RIFF ambiguity.** WAV, AVI, and WebP all begin with `RIFF`. The library returns one of those labels but does not parse the four-byte form type to disambiguate, because that would require reading bytes 8–12 and the table is offset-based. If you need WAV-vs-AVI-vs-WebP, parse further yourself.
- **Mach-O fat vs Java class.** Both use `\xca\xfe\xba\xbe`. The table registers `macho_universal`; a Java `.class` file with the same magic will be mislabelled. Disambiguating requires reading the fat-header arch count, which is out of scope.
- **Truncated input.** A partial signature (e.g. `\x89PN` for PNG) raises `MagicNumberError` rather than returning a guess.
- **Longer match wins.** ZIP variants share the `PK` prefix; the longest matching signature is returned.

## Exports

`sniff`, `sniff_bytes`, `MagicNumberError`, `signatures`, `register`.
