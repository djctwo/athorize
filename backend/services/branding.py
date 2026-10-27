"""Company logo (branding) validation.

The logo lives as a bounded data URI in Organization.settings['branding']
(operator/MSP model: each company an operator manages can carry its own mark,
shown in the sidebar and on Audit Binder covers).

Validation is strict and CONTENT-based:
  - PNG or JPEG only, decided by the MAGIC BYTES of the decoded payload —
    never the claimed MIME type. SVG (or anything script-capable) is rejected
    outright: an SVG data URI is an XSS vector.
  - Decoded size is capped (logos are small chrome, not artwork).
  - Declared PIXEL dimensions are capped too: a tiny compressed PNG can declare
    30000x30000 px and make every browser decode a multi-GB bitmap.

The stored value is CANONICALIZED — rebuilt as data:<sniffed-mime>;base64,<b64>
from the decoded bytes — so downstream consumers (sidebar <img>, Audit Binder
cover) can embed it directly.
"""
import base64
import re
import struct

MAX_LOGO_BYTES = 300 * 1024  # decoded-size cap (~300 KB)
MAX_LOGO_SIDE = 4096  # px, either side (wide wordmarks are fine)
MAX_LOGO_PIXELS = 4 * 1024 * 1024  # ~16 MiB decoded RGBA

# Early rejection before any decoding: base64 inflates ~4/3, so anything past
# this many characters cannot decode under the byte cap anyway.
_MAX_URI_CHARS = 450_000

_DATA_URI_RE = re.compile(r"^data:([a-zA-Z0-9.+/-]+);base64,(.*)$", re.DOTALL)

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"

# Exact shape of the canonical stored URI. Renderers (e.g. the Audit Binder
# cover) use this as a defense-in-depth gate in case settings arrived through
# a backup restore or manual DB edit rather than the validated API.
CANONICAL_LOGO_RE = re.compile(r"^data:image/(?:png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$")


def validate_logo_data_uri(uri: str) -> str:
    """Validate an uploaded logo and return its canonical data URI.

    Raises ValueError with a user-facing message on any rejection.
    """
    if not isinstance(uri, str) or not uri.strip():
        raise ValueError("A logo image is required")
    uri = uri.strip()
    if len(uri) > _MAX_URI_CHARS:
        raise ValueError("Logo is too large (max 300 KB)")
    m = _DATA_URI_RE.match(uri)
    if not m:
        raise ValueError("Logo must be a base64 data URI (data:image/...;base64,...)")
    b64 = re.sub(r"\s+", "", m.group(2))
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        raise ValueError("Logo payload is not valid base64")
    if len(raw) > MAX_LOGO_BYTES:
        raise ValueError("Logo is too large (max 300 KB)")
    if raw.startswith(_PNG_MAGIC):
        mime = "image/png"
        dims = _png_size(raw)
    elif raw.startswith(_JPEG_MAGIC):
        mime = "image/jpeg"
        dims = _jpeg_size(raw)
    else:
        # Covers SVG (XML text), GIF, BMP, WebP, truncated/garbage payloads —
        # anything whose bytes are not a real PNG/JPEG stream.
        raise ValueError("Logo must be a PNG or JPEG image (SVG is not accepted)")
    if dims is None:
        raise ValueError("Logo image is malformed (no readable width/height)")
    width, height = dims
    if not width or not height or width > MAX_LOGO_SIDE or height > MAX_LOGO_SIDE \
            or width * height > MAX_LOGO_PIXELS:
        raise ValueError(
            f"Logo is {width}x{height} px; the maximum is {MAX_LOGO_SIDE} px per side and "
            f"{MAX_LOGO_PIXELS // (1024 * 1024)} megapixels. Resize it and try again."
        )
    return f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"


def _png_size(raw: bytes) -> tuple[int, int] | None:
    """Width/height from the IHDR chunk, which must be the first chunk."""
    if len(raw) < 24 or raw[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", raw[16:24])


# Start-of-frame markers carry the frame size; C4 (DHT), C8 (JPG) and CC (DAC)
# share the range but are not frames.
_JPEG_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def _jpeg_size(raw: bytes) -> tuple[int, int] | None:
    """Width/height from the first SOF segment (walks the segment list)."""
    i = 2
    n = len(raw)
    while i + 4 <= n:
        if raw[i] != 0xFF:
            return None
        marker = raw[i + 1]
        if marker == 0xFF:  # fill byte
            i += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:  # no length field
            i += 2
            continue
        if marker in (0xD9, 0xDA):  # EOI / start of scan before any frame header
            return None
        seg_len = struct.unpack(">H", raw[i + 2:i + 4])[0]
        if marker in _JPEG_SOF:
            if i + 9 > n:
                return None
            height, width = struct.unpack(">HH", raw[i + 5:i + 9])
            return width, height
        if seg_len < 2:
            return None
        i += 2 + seg_len
    return None
