"""Shared plumbing for every file-import path (SIEM/scanner, asset sources,
POA&M/SSP migration, evidence upload).

Three guarantees live here so each importer gets them the same way:

  * Uploads are size-checked WHILE they are read (bounded chunks), never after
    pulling the whole body into memory. ``UploadSizeLimitMiddleware`` adds the
    same bound one layer earlier, on the raw request body, so an oversized
    upload is refused before the multipart parser spools it to disk.
  * Text is decoded the way real exports are written: UTF-8 with or without a
    BOM (Excel "CSV UTF-8"), UTF-16/32 with a BOM (Windows tools), and a
    Windows-1252 / Latin-1 fallback. Binary junk is refused with a clear error.
  * CSV parse failures (over-long fields, bad quoting) become a user-facing
    ``ImportFileError`` (→ HTTP 422 with the line number), never a 500.
"""
from __future__ import annotations

import codecs
import csv
import hashlib
import io
import os
import re
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path

from fastapi import HTTPException, UploadFile

# The csv module's default per-field cap is 131072 chars, far below a real
# Nessus "Plugin Output" or a long POA&M narrative. Every import is already
# bounded by its upload cap, so allow a field up to the largest of those.
csv.field_size_limit(64 * 1024 * 1024)

_CHUNK = 1024 * 1024


class ImportFileError(ValueError):
    """The uploaded file cannot be imported. The message is shown to the user."""


# ---------------------------------------------------------------------------
# Bounded upload reads


def _too_large(max_bytes: int) -> HTTPException:
    return HTTPException(413, f"File exceeds {max_bytes // (1024 * 1024)} MiB limit")


async def read_upload_capped(file: UploadFile, max_bytes: int) -> bytes:
    """Read an upload in bounded chunks; 413 as soon as it passes ``max_bytes``."""
    size = getattr(file, "size", None)
    if isinstance(size, int) and size > max_bytes:
        raise _too_large(max_bytes)
    buf = bytearray()
    while True:
        chunk = await file.read(_CHUNK)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_bytes:
            raise _too_large(max_bytes)
    return bytes(buf)


async def save_upload_capped(file: UploadFile, dest: Path, max_bytes: int) -> str:
    """Stream an upload to ``dest`` while hashing it; returns the SHA-256 hex.

    The file is written to a temporary name next to ``dest`` and renamed only
    when it is complete and within ``max_bytes``; on any failure nothing is
    left on disk.
    """
    size = getattr(file, "size", None)
    if isinstance(size, int) and size > max_bytes:
        raise _too_large(max_bytes)
    tmp = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    total = 0
    try:
        with open(tmp, "wb") as out:
            while True:
                chunk = await file.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise _too_large(max_bytes)
                digest.update(chunk)
                out.write(chunk)
        os.replace(tmp, dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Request-body cap (ASGI)


class _BodyTooLarge(Exception):
    pass


class UploadSizeLimitMiddleware:
    """Refuse a request whose body exceeds the limit for its path.

    ``limit_for(path)`` returns the documented size cap (or None for no
    limit); ``slack`` bytes are allowed on top for multipart framing and form
    fields. A declared Content-Length over cap+slack is refused before the app
    runs; a body that streams past it is cut off at that point. Either way the
    client gets a 413 naming the documented cap, and the server never buffers
    more than cap+slack.
    """

    def __init__(self, app, limit_for: Callable[[str], int | None], slack: int = _CHUNK):
        self.app = app
        self.limit_for = limit_for
        self.slack = slack

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        cap = self.limit_for(scope.get("path", ""))
        if cap is None:
            await self.app(scope, receive, send)
            return
        limit = cap + self.slack

        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = 0
                if declared > limit:
                    await self._reject(send, cap)
                    return
                break

        received = 0
        exceeded = False
        started = False

        async def guarded_receive():
            nonlocal received, exceeded
            if exceeded:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise _BodyTooLarge()
            return message

        async def guarded_send(message):
            nonlocal started
            if exceeded:
                return  # the app's own error for the aborted body is replaced by our 413
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, guarded_receive, guarded_send)
        except Exception:
            if not exceeded:
                raise
        if exceeded and not started:
            await self._reject(send, cap)

    @staticmethod
    async def _reject(send, limit: int) -> None:
        body = (
            '{"detail":"Request body exceeds the %d MiB limit for this endpoint"}' % (limit // (1024 * 1024))
        ).encode()
        await send({"type": "http.response.start", "status": 413, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"connection", b"close"),
        ]})
        await send({"type": "http.response.body", "body": body})


# ---------------------------------------------------------------------------
# Text decoding


def _looks_utf16(raw: bytes) -> str | None:
    """BOM-less UTF-16 (some Windows tools): ASCII text with a NUL in every
    other byte. Returns the codec name, or None."""
    sample = raw[:4096]
    if len(sample) < 4:
        return None
    even = sample[0::2].count(0)
    odd = sample[1::2].count(0)
    half = len(sample) // 2
    if odd > half * 0.6 and even < half * 0.1:
        return "utf-16-le"
    if even > half * 0.6 and odd < half * 0.1:
        return "utf-16-be"
    return None


def _decode_mixed(raw: bytes) -> tuple[str, list[int]]:
    """UTF-8 text with some non-UTF-8 lines (a log concatenated from a UTF-8
    tool and a Windows tool): decode line by line so the valid UTF-8 stays
    intact, falling back to cp1252 (then latin-1) only for the lines that need
    it. Returns the text and the 1-based numbers of the fallback lines."""
    out: list[str] = []
    fallback: list[int] = []
    for n, line in enumerate(raw.splitlines(keepends=True), 1):
        try:
            out.append(line.decode("utf-8"))
            continue
        except UnicodeDecodeError:
            fallback.append(n)
        try:
            out.append(line.decode("cp1252"))
        except UnicodeDecodeError:
            out.append(line.decode("latin-1"))
    return "".join(out), fallback


def _fallback_note(lines: list[int]) -> str:
    shown = ", ".join(str(n) for n in lines[:10]) + (" …" if len(lines) > 10 else "")
    return (f"{len(lines):,} line(s) were not valid UTF-8 and were read as Windows-1252 (line {shown}). "
            "Check those rows for garbled characters; re-export the file as UTF-8 to be sure.")


def decode_text(raw: bytes, notes: list[str] | None = None) -> str:
    """Decode an uploaded text export. Raises ImportFileError for binary data.

    Never silently corrupts text: a UTF-8 file with a few non-UTF-8 lines is
    decoded per line (only those lines fall back to Windows-1252) and a note
    naming them is appended to ``notes`` when the caller passes a list."""
    text: str | None = None
    fallback: list[int] = []
    body = raw
    try:
        if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)) and len(raw) % 4 == 0:
            text = raw.decode("utf-32")
        elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            text = raw.decode("utf-16")
        elif raw.startswith(codecs.BOM_UTF8):
            body = raw[len(codecs.BOM_UTF8):]
        elif b"\x00" in raw[:4096] and (codec := _looks_utf16(raw)):
            text = raw.decode(codec)
    except UnicodeDecodeError:
        raise ImportFileError("The file looks like UTF-16/32 text but could not be decoded.")
    if text is None:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            if body is raw and not _has_utf8_multibyte(raw):
                # No valid UTF-8 sequence anywhere: a plain Windows-1252 export.
                try:
                    text = raw.decode("cp1252")
                except UnicodeDecodeError:
                    text = raw.decode("latin-1")
            else:
                text, fallback = _decode_mixed(body)
    text = text.lstrip("\ufeff")
    if "\x00" in text:
        raise ImportFileError("The file appears to be binary, not a text export (CSV, JSON, XML or log).")
    if fallback and notes is not None:
        notes.append(_fallback_note(fallback))
    return text


_UTF8_MULTIBYTE = re.compile(rb"[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf4][\x80-\xbf]{3}")


def _has_utf8_multibyte(raw: bytes) -> bool:
    """True when the bytes contain at least one well-formed multi-byte UTF-8
    sequence, i.e. the file is (at least partly) UTF-8 rather than cp1252."""
    return _UTF8_MULTIBYTE.search(raw) is not None


# ---------------------------------------------------------------------------
# CSV


def csv_dicts(content: str) -> Iterator[dict]:
    """csv.DictReader over ``content`` that accepts any line ending (including
    bare CR from Excel for Mac) and turns csv.Error into ImportFileError."""
    reader = csv.DictReader(io.StringIO(content, newline=""))
    try:
        yield from reader
    except csv.Error as exc:
        raise ImportFileError(f"Malformed CSV near line {reader.line_num}: {exc}") from exc


def csv_table(content: str) -> list[list[str]]:
    """All CSV records as lists of cells (same tolerance/errors as csv_dicts)."""
    reader = csv.reader(io.StringIO(content, newline=""))
    try:
        return list(reader)
    except csv.Error as exc:
        raise ImportFileError(f"Malformed CSV near line {reader.line_num}: {exc}") from exc


# ---------------------------------------------------------------------------
# Per-file accounting


class RowReport:
    """Rows a parser produced plus everything it could NOT use, so every
    import response can say how many rows were imported, skipped (and why)
    and dropped by the row cap."""

    def __init__(self, max_rows: int):
        self.max_rows = max_rows
        self.rows: list[dict] = []
        self.skipped: Counter[str] = Counter()
        self.truncated = 0
        self.notes: list[str] = []  # file-level remarks (e.g. decode fallbacks)

    def add(self, item: dict) -> None:
        if len(self.rows) >= self.max_rows:
            self.truncated += 1
            return
        self.rows.append(item)

    def skip(self, reason: str) -> None:
        self.skipped[reason] += 1

    def summary(self) -> dict:
        return {
            "skipped_rows": sum(self.skipped.values()),
            "skip_reasons": dict(self.skipped),
            "truncated": self.truncated > 0,
            "truncated_count": self.truncated,
            "max_rows": self.max_rows,
        }

    def skip_text(self) -> str:
        total = sum(self.skipped.values())
        if not total:
            return ""
        reasons = "; ".join(f"{r} ({n:,})" for r, n in self.skipped.most_common())
        return f"{total:,} row(s) skipped: {reasons}"

    def warnings(self, noun: str) -> list[str]:
        out: list[str] = []
        if self.truncated:
            out.append(
                f"Only the first {self.max_rows:,} {noun} in this file are imported; "
                f"{self.truncated:,} more were not (row limit). Split the file and import the rest."
            )
        if self.skipped:
            out.append(self.skip_text() + ".")
        out.extend(self.notes)
        return out
