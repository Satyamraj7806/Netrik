"""Small server-side SVG charts (no chart library). Colours come from CSS variables."""

from __future__ import annotations

import math

from markupsafe import Markup, escape


def donut(segments: list, size: int = 168, thickness: int = 20, center: str = "", sub: str = "") -> Markup:
    """segments: [(label, value, css_colour)]"""
    r = (size - thickness) / 2
    circ = 2 * math.pi * r
    total = sum(v for _, v, _ in segments) or 0
    c = size / 2
    parts = [f'<svg class="donut" viewBox="0 0 {size} {size}" role="img" aria-label="{escape(center)} {escape(sub)}">',
             f'<circle cx="{c}" cy="{c}" r="{r}" fill="none" stroke="var(--line)" stroke-width="{thickness}"/>']
    offset = 0.0
    for i, (label, v, color) in enumerate(segments):
        if not v or not total:
            continue
        ln = max(0.0, circ * v / total - 2)
        parts.append(f'<circle class="seg" cx="{c}" cy="{c}" r="{r}" fill="none" stroke="{color}" stroke-width="{thickness}" '
                     f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {c} {c})" '
                     f'style="--len:{ln:.2f};--gap:{circ - ln:.2f};animation-delay:{i * 120}ms"><title>{escape(label)}: {v}</title></circle>')
        offset += circ * v / total
    parts.append(f'<text x="{c}" y="{c - 2}" text-anchor="middle" class="d-num">{escape(center)}</text>'
                 f'<text x="{c}" y="{c + 18}" text-anchor="middle" class="d-sub">{escape(sub)}</text></svg>')
    return Markup("".join(parts))


def bars(values: list, labels: list, width: int = 440, height: int = 120) -> Markup:
    n = len(values) or 1
    top = max(values + [1])
    pad, gap = 6, 6
    bw = (width - pad * 2 - gap * (n - 1)) / n
    out = [f'<svg class="bars" viewBox="0 0 {width} {height + 22}" role="img" aria-label="Devices with evidence per day">']
    for i in range(0, 5):
        y = 4 + (height - 4) * i / 4
        out.append(f'<line x1="0" x2="{width}" y1="{y:.1f}" y2="{y:.1f}" stroke="var(--line)" stroke-width="1" stroke-dasharray="2 4"/>')
    for i, v in enumerate(values):
        h = (height - 8) * v / top
        x = pad + i * (bw + gap)
        out.append(f'<rect class="bar-rect" x="{x:.1f}" y="{height - h:.1f}" width="{bw:.1f}" height="{max(h, 1.5):.1f}" rx="3" fill="var(--acc)" '
                   f'style="animation-delay:{i * 45}ms;transform-origin:{x + bw / 2:.1f}px {height}px"><title>{escape(labels[i])}: {v}</title></rect>')
        if n <= 14 or i % 2 == 0:
            out.append(f'<text x="{x + bw / 2:.1f}" y="{height + 15}" text-anchor="middle" class="ax">{escape(labels[i][-2:])}</text>')
    out.append("</svg>")
    return Markup("".join(out))
