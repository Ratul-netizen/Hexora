#!/usr/bin/env python3
"""Generate Hexora's application icons.

Kept as a script rather than hand-drawn binaries so the icon set can be regenerated
reproducibly, and so a colour change is a one-line diff rather than an opaque blob.

Draws a pointy-top hexagon (for "Hexora") in the product accent colour, supersampled
for antialiasing. Writes:

    apps/desktop/src-tauri/icons/icon.ico   (Windows resource + tray)
    apps/desktop/src-tauri/icons/*.png      (Linux/macOS bundle sizes)

Depends only on the standard library. Run from the repository root:

    python scripts/generate_icons.py
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

# Product accent, matching --accent in frontend/src/styles.css.
ACCENT = (0x7C, 0x5C, 0xFF)
SUPERSAMPLE = 4

ICO_SIZES = (16, 32, 48, 64, 128, 256)
PNG_SIZES = (32, 128, 256, 512)


def hexagon_vertices(size: float) -> list[tuple[float, float]]:
    """Pointy-top hexagon inscribed in a `size` square, with a small margin."""
    import math

    cx = cy = size / 2
    radius = size / 2 * 0.92
    return [
        (
            cx + radius * math.cos(math.radians(90 + 60 * i)),
            cy - radius * math.sin(math.radians(90 + 60 * i)),
        )
        for i in range(6)
    ]


def inside(point: tuple[float, float], polygon: list[tuple[float, float]]) -> bool:
    """Ray-casting point-in-polygon test."""
    x, y = point
    result = False
    j = len(polygon) - 1
    for i, (xi, yi) in enumerate(polygon):
        xj, yj = polygon[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            result = not result
        j = i
    return result


def render_rgba(size: int) -> bytes:
    """Render the icon as raw RGBA rows, top to bottom."""
    polygon = hexagon_vertices(size * SUPERSAMPLE)
    pixels = bytearray()
    for y in range(size):
        for x in range(size):
            # Supersample, then average coverage into the alpha channel.
            hits = 0
            for sy in range(SUPERSAMPLE):
                for sx in range(SUPERSAMPLE):
                    sample = (
                        x * SUPERSAMPLE + sx + 0.5,
                        y * SUPERSAMPLE + sy + 0.5,
                    )
                    if inside(sample, polygon):
                        hits += 1
            alpha = round(255 * hits / (SUPERSAMPLE * SUPERSAMPLE))
            pixels += bytes((*ACCENT, alpha))
    return bytes(pixels)


def write_png(path: Path, size: int, rgba: bytes) -> None:
    """Write a minimal RGBA PNG."""
    raw = bytearray()
    stride = size * 4
    for y in range(size):
        raw.append(0)  # filter type 0 (None)
        raw += rgba[y * stride : (y + 1) * stride]

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def bmp_for_ico(size: int, rgba: bytes) -> bytes:
    """A 32-bit BGRA DIB with an AND mask, as an ICO image entry expects.

    The DIB header claims double the real height: the format appends a 1-bit
    transparency mask below the colour data, and the header covers both.
    """
    header = struct.pack(
        "<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, size * size * 4, 0, 0, 0, 0
    )
    # DIB rows run bottom-to-top, and channels are BGRA rather than RGBA.
    body = bytearray()
    for y in range(size - 1, -1, -1):
        row = rgba[y * size * 4 : (y + 1) * size * 4]
        for x in range(size):
            r, g, b, a = row[x * 4 : x * 4 + 4]
            body += bytes((b, g, r, a))

    # AND mask: unused because alpha carries transparency, but structurally required.
    mask_stride = ((size + 31) // 32) * 4
    body += bytes(mask_stride * size)
    return header + bytes(body)


def write_ico(path: Path, images: dict[int, bytes]) -> None:
    """Write a multi-resolution ICO."""
    entries = bytearray()
    payload = bytearray()
    offset = 6 + 16 * len(images)

    for size in sorted(images):
        data = bmp_for_ico(size, images[size])
        entries += struct.pack(
            "<BBBBHHII",
            # 256 is stored as 0: the field is a single byte.
            0 if size >= 256 else size,
            0 if size >= 256 else size,
            0,
            0,
            1,
            32,
            len(data),
            offset,
        )
        payload += data
        offset += len(data)

    path.write_bytes(struct.pack("<HHH", 0, 1, len(images)) + bytes(entries) + bytes(payload))


def main() -> None:
    icons = Path(__file__).resolve().parent.parent / "apps/desktop/src-tauri/icons"
    icons.mkdir(parents=True, exist_ok=True)

    rendered = {size: render_rgba(size) for size in sorted({*ICO_SIZES, *PNG_SIZES})}

    write_ico(icons / "icon.ico", {size: rendered[size] for size in ICO_SIZES})
    print(f"wrote {icons / 'icon.ico'}")

    for size in PNG_SIZES:
        name = "icon.png" if size == 512 else f"{size}x{size}.png"
        write_png(icons / name, size, rendered[size])
        print(f"wrote {icons / name}")


if __name__ == "__main__":
    main()
