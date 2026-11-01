#!/usr/bin/env python3
"""Render Yeager's icons from the vector logo.

The source is `assets/logo/yeager.svg`: an ascending wing in an accent-to-light
ombre on a dark rounded tile. It is rendered once at 1024 px to the master
`assets/icons/src/yeager.png` (with `rsvg-convert`, from librsvg), and every
size is reduced from that master directly, so each one is as sharp as the art
allows. Without `rsvg-convert` the committed master is used as is.

Produces:
  assets/icons/src/yeager.png  1024px master (rendered from the SVG)
  assets/icons/yeager.ico      multi-size app / desktop / taskbar icon
  assets/icons/yeager.png      256px window icon / preview
  assets/icons/tray.bin        the tray icon at each small size, with a rim
                               mask and a wing mask: while Yeager is on, the
                               app paints the rim and the wing in the UI accent

The sidebar mark is drawn by the app itself (BrandMark in widgets.slint) from
the same wing path, so it follows the accent too.

Run from the repo root:  python3 tools/make_icons.py
(needs Pillow, numpy, and rsvg-convert to re-render the master)
"""
import os
import re
import shutil
import struct
import subprocess
import tempfile

import numpy as np
from PIL import Image, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVG = os.path.join(ROOT, "assets", "logo", "yeager.svg")
MASTER = os.path.join(ROOT, "assets", "icons", "src", "yeager.png")

# Tray sizes: 16 px at 100% DPI up to 40 at 250%, plus 48/64 for larger setups.
TRAY_SIZES = [16, 20, 24, 32, 40, 48, 64]


def odd(n):
    # Pillow's rank filters crash on size 1, so never go below 3.
    return max(3, 2 * int(n) + 1)


def rasterize(svg_text, size):
    with tempfile.TemporaryDirectory() as tmp:
        src, out = os.path.join(tmp, "in.svg"), os.path.join(tmp, "out.png")
        with open(src, "w", encoding="utf-8") as f:
            f.write(svg_text)
        subprocess.run(["rsvg-convert", "-w", str(size), "-h", str(size), src, "-o", out], check=True)
        return Image.open(out).convert("RGBA")


def wing_only(svg_text):
    """The SVG with just the wing, in plain white: its alpha is the wing mask."""
    d = re.search(r'<path id="wing-path"[^>]* d="([^"]+)"', svg_text).group(1)
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">'
            f'<path fill="#fff" d="{d}"/></svg>')


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
    out = os.path.join(ROOT, "assets", "icons")
    with open(SVG, encoding="utf-8") as f:
        svg = f.read()
    if shutil.which("rsvg-convert"):
        os.makedirs(os.path.dirname(MASTER), exist_ok=True)
        rasterize(svg, 1024).save(MASTER, optimize=True)
        wing = rasterize(wing_only(svg), 1024).getchannel("A")
    else:
        print("rsvg-convert not found: using the committed master, no wing mask")
        wing = None
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

    # Tray: per size, the icon (RGBA), its rim mask and its wing mask (one
    # byte per pixel each). platform.rs picks the size for the DPI and, while
    # Yeager is on, paints the rim and the wing in the current accent color.
    if wing is None:
        return
    with open(os.path.join(out, "tray.bin"), "wb") as f:
        f.write(struct.pack("<I", len(TRAY_SIZES)))
        for s in TRAY_SIZES:
            f.write(struct.pack("<I", s))
            f.write(render(master, s).tobytes())
            f.write(rim(master, s).tobytes())
            f.write(wing.resize((s, s), Image.LANCZOS).tobytes())

    print("Wrote master, yeager.ico, yeager.png, tray.bin to", out)


if __name__ == "__main__":
    main()
