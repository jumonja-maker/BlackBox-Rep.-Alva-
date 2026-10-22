"""Generate original BLACK.BOX Universal app icon (ICO + PNG), no stock assets.

Pixel geometry inspired by 1990s monitor outlines. Run at packaging time;
Pillow is a build-only dependency and is not required by end users.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


def draw_icon(size: int) -> Image.Image:
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    # Draw once at 64 logical pixels; scale with NEAREST for retro contours.
    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(image)
    ink = "#2c2a42"
    teal = "#087f7b"
    mint = "#8bdfb2"
    coral = "#ee735b"
    cream = "#fff8e4"
    lilac = "#c7a9d1"

    # Teal desktop tile, raised pixel edges and warm offset border.
    d.rounded_rectangle((3, 3, 60, 60), radius=7, fill=teal, outline=ink, width=3)
    d.rectangle((7, 8, 55, 10), fill=mint)
    d.rectangle((9, 13, 54, 46), fill=cream, outline=ink, width=3)
    d.rectangle((14, 18, 49, 41), fill=ink)
    d.rectangle((17, 21, 46, 38), fill=teal)
    # Original pulse symbol: a 'diagnostic eye' rhythm on the monitor.
    d.line([(20, 32), (25, 32), (29, 25), (34, 36),
            (38, 29), (44, 29)], fill=mint, width=3, joint="curve")
    d.rectangle((23, 46, 40, 50), fill=lilac, outline=ink)
    d.rectangle((17, 50, 46, 54), fill=cream, outline=ink, width=2)
    # Pixel sparkle in upper-right corner.
    d.line((53, 14, 53, 23), fill=coral, width=2)
    d.line((49, 19, 57, 19), fill=coral, width=2)
    d.rectangle((7, 55, 13, 58), fill=coral)
    return image.resize((size, size), Image.Resampling.NEAREST).convert("RGBA")


def main() -> None:
    target = Path(__file__).resolve().parent.parent / "assets"
    target.mkdir(exist_ok=True)
    icons = [draw_icon(size) for size in (16, 24, 32, 48, 64, 128, 256)]
    icons[-1].save(target / "blackbox.png", format="PNG")
    icons[-1].save(target / "blackbox.ico", format="ICO",
                   sizes=[(n, n) for n in (16, 24, 32, 48, 64, 128, 256)],
                   append_images=icons[:-1])
    print("Original retro BLACK.BOX icon generated")


if __name__ == "__main__":
    main()
