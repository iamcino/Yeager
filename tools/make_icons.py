#!/usr/bin/env python3
"""Render Yeager's icons from Cino's master artwork.

The master is `assets/icons/src/yeager.png`: the finished "Wings of Freedom"
tile (white wing behind, blue wing in front, on a dark rounded square) at
1024 px with a transparent background. Every size is reduced from it
directly, never scaled up, so each one is as sharp as the art allows.

Produces:
  assets/icons/yeager.ico   multi-size app / desktop / taskbar icon
  assets/icons/yeager.png   256px window icon / preview
  assets/icons/brand.png    56px sidebar brand mark (28px @2x)
  assets/icons/tray.bin     the tray icon at each small size, with a rim mask
                            the app paints in the UI accent while Yeager is on

Run from the repo root:  python3 tools/make_icons.py   (needs Pillow, numpy)

To replace the master with a new export on a white background:
  python3 tools/make_icons.py --import path/to/export.png
"""
import os
import struct
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER = os.path.join(ROOT, "assets", "icons", "src", "yeager.png")

# Tray sizes: 16 px at 100% DPI up to 40 at 250%, plus 48/64 for larger setups.
TRAY_SIZES = [16, 20, 24, 32, 40, 48, 64]


def odd(n):
    # Pillow's rank filters crash on size 1, so never go below 3.
    return max(3, 2 * int(n) + 1)


def import_master(path):
    """Cuts an export on a white background out to a transparent master.

    The export's tile runs a few pixels past the canvas, so its straight sides
    are cut flat and their rim is lost. The tile is therefore redrawn: its
    outline (a superellipse) is fitted to the parts the canvas does not cut,
    shrunk just enough to fit, and drawn anti-aliased with an even grey rim on
    all four sides. Inside, the dark surface is repainted from its own colours
    so compression noise and smudges (an export watermark, say) are gone."""
    rgb = np.array(Image.open(path).convert("RGB"))
    near_white = Image.fromarray(((rgb.min(axis=2) > 200) * 255).astype(np.uint8), "L").copy()
    w, h = near_white.size
    for corner in [(0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)]:
        ImageDraw.floodfill(near_white, corner, 128)
    tile = np.array(near_white) != 128

    n, half = fit_outline(tile)
    rim_width = w / 256
    inside = (w - 1) / 2 - 1.5  # the new half-size: inside the canvas, with room to anti-alias
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float64)
    cx, cy = (w - 1) / 2, (h - 1) / 2
    # Roughly the signed distance to the outline, in pixels (negative inside).
    dist = ((np.abs(xx - cx) ** n + np.abs(yy - cy) ** n) ** (1 / n)) - inside
    alpha = np.clip(0.5 - dist, 0, 1)
    rim = np.clip(dist + rim_width + 0.5, 0, 1)

    # The rim's grey, from the export's own rim (its outer pixels).
    old_rim = tile & (dist + (inside - half) > -rim_width)
    grey = np.median(rgb[old_rim & (rgb.max(axis=2) > 60)], axis=0)

    # The dark surface is a plain vertical gradient; repaint it row by row
    # from its median.
    surface = tile & (dist < -rim_width) & (rgb.max(axis=2) < 75)
    # Export watermarks (a grey sparkle) sit in the bottom-right corner, clear
    # of the wings: count any grey there as surface too, so it is painted over.
    grey_px = (rgb.max(axis=2).astype(int) - rgb.min(axis=2) < 25) & (rgb.max(axis=2) < 200)
    surface |= tile & (dist < -rim_width) & grey_px & (xx > w * 0.8) & (yy > h * 0.8)
    for y in range(h):
        row = surface[y]
        if row.any():
            rgb[y, row] = np.median(rgb[y, row], axis=0).astype(np.uint8)

    out = rgb * (1 - rim[..., None]) + grey * rim[..., None]
    img = np.dstack([out, alpha * 255]).round().astype(np.uint8)
    Image.fromarray(img, "RGBA").resize((1024, 1024), Image.LANCZOS).save(MASTER, optimize=True)
    print("Wrote", MASTER, "outline n=%.2f, rim" % n, tuple(int(c) for c in grey))


def fit_outline(tile):
    """The superellipse |x|^n + |y|^n = a^n that best matches the tile's edge
    where the canvas does not cut it. Returns (n, a) in pixels."""
    h, w = tile.shape
    cx, cy = (w - 1) / 2, (h - 1) / 2
    angles, radii = [], []
    for ang in np.linspace(0, 2 * np.pi, 360, endpoint=False):
        dx, dy = np.cos(ang), np.sin(ang)
        r = np.arange(0, max(w, h))
        x = np.round(cx + dx * r).astype(int)
        y = np.round(cy + dy * r).astype(int)
        ok = (x >= 0) & (x < w) & (y >= 0) & (y < h)
        x, y = x[ok], y[ok]
        out = np.nonzero(~tile[y, x])[0]
        if not len(out):
            continue  # runs off the canvas: cut
        edge = out[0]
        if 2 < x[edge] < w - 3 and 2 < y[edge] < h - 3:
            angles.append(ang)
            radii.append(edge - 0.5)
    angles, radii = np.array(angles), np.array(radii)
    best = None
    for n in np.arange(2.0, 8.0, 0.05):
        g = (np.abs(np.cos(angles)) ** n + np.abs(np.sin(angles)) ** n) ** (-1 / n)
        a = (g @ radii) / (g @ g)
        err = np.mean((a * g - radii) ** 2)
        if best is None or err < best[0]:
            best = (err, n, a)
    return best[1], best[2]


def render(master, size):
    return master.resize((size, size), Image.LANCZOS)


def rim(master, size):
    """Where the tray paints the accent while Yeager is on: a bright line along
    the tile's edge with a soft glow falling inward. At least ~1.3 px wide at
    16 px so it survives the reduction. Rendered at 4x, returned at `size`."""
    ss = size * 4
    tile = np.array(master.resize((ss, ss), Image.LANCZOS).getchannel("A")).astype(np.float32)
    width = max(1.5, size / 14) * 4
    # Pad so the sides touching the canvas edge erode like the corners do.
    pad = int(width) + 2
    padded = Image.fromarray(np.pad(tile, pad).astype(np.uint8)).filter(ImageFilter.MinFilter(odd(width)))
    eroded = np.array(padded).astype(np.float32)[pad:-pad, pad:-pad]
    line = np.clip(tile - eroded, 0, 255)
    glow = np.array(Image.fromarray(line.astype(np.uint8)).filter(ImageFilter.GaussianBlur(width * 1.2)))
    mask = np.maximum(line, np.minimum(glow.astype(np.float32), tile) * 0.7)
    return Image.fromarray(mask.round().astype(np.uint8), "L").resize((size, size), Image.LANCZOS)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--import":
        import_master(sys.argv[2])
    out = os.path.join(ROOT, "assets", "icons")
    master = Image.open(MASTER).convert("RGBA")

    # Full size ladder so Windows picks a native size at every DPI. Pass every
    # render via append_images; with `sizes` alone Pillow would just
    # downscale the 256px image for each entry.
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    images = [render(master, s) for s in sizes]
    images[-1].save(
        os.path.join(out, "yeager.ico"),
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[:-1],
    )
    images[-1].save(os.path.join(out, "yeager.png"))

    # Sidebar brand mark: 28px in the UI, rendered at 2x so it stays sharp on
    # high-DPI screens without Slint having to shrink the 256px image.
    render(master, 56).save(os.path.join(out, "brand.png"))

    # Tray: per size, the icon (RGBA) and its rim mask (one byte per pixel).
    # platform.rs picks the size for the DPI and paints the rim in the current
    # accent color, so the glow follows the accent chosen in the app.
    with open(os.path.join(out, "tray.bin"), "wb") as f:
        f.write(struct.pack("<I", len(TRAY_SIZES)))
        for s in TRAY_SIZES:
            f.write(struct.pack("<I", s))
            f.write(render(master, s).tobytes())
            f.write(rim(master, s).tobytes())

    print("Wrote yeager.ico, yeager.png, brand.png, tray.bin to", out)


if __name__ == "__main__":
    main()
