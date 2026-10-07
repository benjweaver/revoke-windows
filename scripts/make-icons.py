"""Renders Revoke's tray icons and assembles the app icon.

    python scripts/make-icons.py

The app icon is the one Revoke for macOS uses: its PNGs, copied into
src/Revoke/Assets, go into icon.ico unchanged. The tray icons are drawn here, at
each size the notification area uses (16 to 48 pixels, for 100% to 300%
scaling): a lock, closed in the taskbar's text color while watched apps are
stopped, and open in orange while any of them is running. Standard library only.
"""

import os
import struct

ICONS = os.path.join(os.path.dirname(__file__), "..", "src", "Revoke", "Assets")
TRAY_SIZES = [16, 20, 24, 32, 40, 48]
SUPERSAMPLE = 8


def rounded_rect(x, y, left, top, right, bottom, radius):
    cx = min(max(x, left + radius), right - radius)
    cy = min(max(y, top + radius), bottom - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2 and left <= x <= right and top <= y <= bottom


def lock(x, y, open_):
    """Whether point (x, y), in 32-pixel units, is inside the lock glyph."""
    # The body, with a keyhole cut out.
    if rounded_rect(x, y, 6.5, 14.5, 25.5, 29, 3.2):
        keyhole = (x - 16) ** 2 + (y - 20.5) ** 2 <= 2.3 ** 2 or (14.9 <= x <= 17.1 and 20.5 <= y <= 25)
        return not keyhole
    # The shackle: a half ring on two legs. Open, it lifts and the right leg
    # comes out of the body.
    lift = 4.0 if open_ else 0.0
    cx, cy, outer, inner = 16.0, 10.5 - lift, 7.2, 4.4
    if y <= cy:
        return inner ** 2 <= (x - cx) ** 2 + (y - cy) ** 2 <= outer ** 2
    left_leg = cx - outer <= x <= cx - inner and y <= 15.0
    right_leg = cx + inner <= x <= cx + outer and y <= (cy + 2.2 if open_ else 15.0)
    return left_leg or right_leg


def render(size, color, open_):
    """RGBA rows of the lock at `size` pixels. The glyph is designed on a 32-unit grid."""
    rgba = bytearray(size * size * 4)
    scale = 32 / size
    step = 1 / SUPERSAMPLE
    for py in range(size):
        for px in range(size):
            hits = sum(
                lock((px + (i + 0.5) * step) * scale, (py + (j + 0.5) * step) * scale, open_)
                for i in range(SUPERSAMPLE)
                for j in range(SUPERSAMPLE)
            )
            alpha = round(255 * hits / SUPERSAMPLE ** 2)
            o = (py * size + px) * 4
            rgba[o:o + 4] = bytes(color) + bytes([alpha])
    return rgba


def dib(size, rgba):
    """A 32-bit BGRA bitmap icon image: header, bottom-up pixels, and an empty AND mask."""
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    rows = []
    for y in reversed(range(size)):
        row = bytearray()
        for x in range(size):
            r, g, b, a = rgba[(y * size + x) * 4:(y * size + x) * 4 + 4]
            row += bytes([b, g, r, a])
        rows.append(bytes(row))
    mask_row = ((size + 31) // 32) * 4
    return header + b"".join(rows) + bytes(mask_row * size)


def ico(images):
    """An .ico holding the given images (PNG or bitmap), keyed by size."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, data = b"", b""
    for size, blob in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset + len(data))
        data += blob
    return header + entries + data


def main():
    tray = {
        "tray-closed-dark.ico": ((255, 255, 255), False),  # on a dark taskbar
        "tray-closed-light.ico": ((26, 26, 26), False),  # on a light taskbar
        "tray-open.ico": ((247, 99, 12), True),  # Windows' orange, on either
    }
    for name, (color, open_) in tray.items():
        # Bitmap images rather than PNG: LoadImage reads those at every size.
        images = [(size, dib(size, render(size, color, open_))) for size in TRAY_SIZES]
        with open(os.path.join(ICONS, name), "wb") as f:
            f.write(ico(images))

    sizes = [16, 32, 64, 128, 256]
    pngs = []
    for size in sizes:
        with open(os.path.join(ICONS, f"icon_{size}.png"), "rb") as f:
            pngs.append((size, f.read()))
    with open(os.path.join(ICONS, "icon.ico"), "wb") as f:
        f.write(ico(pngs))
    print("wrote", ", ".join(list(tray) + ["icon.ico"]))


if __name__ == "__main__":
    main()
