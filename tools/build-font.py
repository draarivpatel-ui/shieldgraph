"""Builds ShieldGraph Plot, the monoline display face used for the wordmark and
headings. Every glyph is drawn as pen strokes (lines, elliptical arcs, dots) on a
1000-unit grid and outlined here, the way a plotter pen would draw it.

Usage: python3 tools/build-font.py   (needs fontTools and brotli)
Output: fonts/shieldgraph-plot.woff2
"""
import math
import os

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

UPM = 1000
W = 84          # pen width
M = 66          # side bearing beyond the pen edge
CAP, XH, ASC, DESC = 700, 500, 720, -190


def L(*pts):
    return ('L', pts)


def A(cx, cy, rx, ry, a0, a1):
    return ('A', (cx, cy, rx, ry, a0, a1))


def D(x, y):
    return ('D', (x, y))


def circle(cx, cy, rx, ry=None):
    return A(cx, cy, rx, ry if ry is not None else rx, 0, 360)


G = {
    'A': (600, [L((20, 0), (300, 700), (580, 0)), L((125, 230), (475, 230))]),
    'B': (480, [L((0, 0), (0, 700), (280, 700)), A(280, 525, 175, 175, 90, -90), L((280, 350), (0, 350), (300, 350)), A(300, 175, 175, 175, 90, -90), L((300, 0), (0, 0))]),
    'C': (600, [A(300, 350, 300, 350, 42, 318)]),
    'D': (520, [L((220, 0), (0, 0), (0, 700), (220, 700)), A(220, 350, 300, 350, 90, -90)]),
    'E': (440, [L((440, 700), (0, 700), (0, 0), (440, 0)), L((0, 350), (360, 350))]),
    'F': (440, [L((440, 700), (0, 700), (0, 0)), L((0, 350), (360, 350))]),
    'G': (600, [A(300, 350, 300, 350, 38, 360), L((600, 350), (370, 350))]),
    'H': (480, [L((0, 0), (0, 700)), L((480, 0), (480, 700)), L((0, 350), (480, 350))]),
    'I': (0, [L((0, 0), (0, 700))]),
    'J': (360, [L((360, 700), (360, 190)), A(180, 190, 180, 190, 0, -180)]),
    'K': (460, [L((0, 0), (0, 700)), L((440, 700), (0, 250)), L((160, 410), (460, 0))]),
    'L': (400, [L((0, 700), (0, 0), (400, 0))]),
    'M': (600, [L((0, 0), (0, 700), (300, 170), (600, 700), (600, 0))]),
    'N': (480, [L((0, 0), (0, 700), (480, 0), (480, 700))]),
    'O': (680, [circle(340, 350, 340, 350)]),
    'P': (450, [L((0, 0), (0, 700), (270, 700)), A(270, 520, 180, 180, 90, -90), L((270, 340), (0, 340))]),
    'Q': (680, [circle(340, 350, 340, 350), L((430, 170), (680, -50))]),
    'R': (460, [L((0, 0), (0, 700), (270, 700)), A(270, 520, 180, 180, 90, -90), L((270, 340), (0, 340)), L((240, 340), (460, 0))]),
    'S': (480, [A(240, 525, 230, 175, 25, 270), A(240, 175, 240, 175, 90, -155)]),
    'T': (520, [L((0, 700), (520, 700)), L((260, 700), (260, 0))]),
    'U': (480, [L((0, 700), (0, 230)), A(240, 230, 240, 230, 180, 360), L((480, 230), (480, 700))]),
    'V': (560, [L((0, 700), (280, 0), (560, 700))]),
    'W': (760, [L((0, 700), (190, 0), (380, 560), (570, 0), (760, 700))]),
    'X': (500, [L((0, 700), (500, 0)), L((500, 700), (0, 0))]),
    'Y': (520, [L((0, 700), (260, 340), (520, 700)), L((260, 340), (260, 0))]),
    'Z': (480, [L((0, 700), (480, 700), (0, 0), (480, 0))]),
    'a': (440, [circle(220, 250, 220, 250), L((440, 500), (440, 0))]),
    'b': (440, [L((0, 720), (0, 0)), circle(220, 250, 220, 250)]),
    'c': (450, [A(230, 250, 230, 250, 45, 315)]),
    'd': (440, [circle(220, 250, 220, 250), L((440, 720), (440, 0))]),
    'e': (440, [L((0, 250), (440, 250)), A(220, 250, 220, 250, 0, 318)]),
    'f': (300, [L((80, 0), (80, 560)), A(220, 560, 140, 160, 180, 40), L((0, 480), (260, 480))]),
    'g': (440, [circle(220, 250, 220, 250), L((440, 500), (440, -30)), A(220, -30, 220, 160, 0, -165)]),
    'h': (400, [L((0, 720), (0, 0)), A(200, 300, 200, 200, 180, 0), L((400, 300), (400, 0))]),
    'i': (0, [L((0, 0), (0, 500)), D(0, 680)]),
    'j': (100, [L((100, 500), (100, -60)), A(-10, -60, 110, 130, 0, -150), D(100, 680)]),
    'k': (380, [L((0, 720), (0, 0)), L((360, 500), (0, 190)), L((130, 300), (380, 0))]),
    'l': (0, [L((0, 720), (0, 0))]),
    'm': (660, [L((0, 0), (0, 500)), A(165, 330, 165, 170, 180, 0), L((330, 330), (330, 0)), A(495, 330, 165, 170, 180, 0), L((660, 330), (660, 0))]),
    'n': (400, [L((0, 0), (0, 500)), A(200, 300, 200, 200, 180, 0), L((400, 300), (400, 0))]),
    'o': (460, [circle(230, 250, 230, 250)]),
    'p': (440, [L((0, 500), (0, -190)), circle(220, 250, 220, 250)]),
    'q': (440, [circle(220, 250, 220, 250), L((440, 500), (440, -190))]),
    'r': (320, [L((0, 0), (0, 500)), A(220, 280, 220, 220, 180, 62)]),
    's': (360, [A(180, 375, 170, 125, 25, 270), A(180, 125, 180, 125, 90, -155)]),
    't': (280, [L((100, 700), (100, 120)), A(220, 120, 120, 120, 180, 270), L((0, 500), (260, 500))]),
    'u': (400, [L((0, 500), (0, 200)), A(200, 200, 200, 200, 180, 360), L((400, 500), (400, 0))]),
    'v': (440, [L((0, 500), (220, 0), (440, 500))]),
    'w': (600, [L((0, 500), (150, 0), (300, 400), (450, 0), (600, 500))]),
    'x': (400, [L((0, 500), (400, 0)), L((400, 500), (0, 0))]),
    'y': (440, [L((0, 500), (220, 20)), L((440, 500), (150, -190))]),
    'z': (400, [L((0, 500), (400, 500), (0, 0), (400, 0))]),
    '0': (520, [circle(260, 350, 260, 350)]),
    '1': (240, [L((0, 560), (180, 700), (180, 0))]),
    '2': (460, [A(230, 480, 220, 220, 160, -40), L((398, 339), (0, 0), (460, 0))]),
    '3': (460, [A(220, 525, 210, 175, 150, -90), A(230, 175, 230, 175, 90, -150)]),
    '4': (480, [L((360, 0), (360, 700), (0, 200), (480, 200))]),
    '5': (460, [L((420, 700), (60, 700), (40, 390)), A(230, 220, 230, 220, 142, -150)]),
    '6': (460, [circle(230, 230, 230, 230), L((30, 320), (300, 700))]),
    '7': (460, [L((0, 700), (460, 700), (140, 0))]),
    '8': (460, [circle(230, 530, 190, 170), circle(230, 190, 230, 190)]),
    '9': (460, [circle(230, 470, 230, 230), L((430, 380), (160, 0))]),
    '.': (0, [D(0, 0)]),
    ',': (30, [L((30, 20), (-20, -120))]),
    ':': (0, [D(0, 0), D(0, 420)]),
    ';': (30, [L((30, 20), (-20, -120)), D(30, 420)]),
    '-': (260, [L((0, 300), (260, 300))]),
    "'": (0, [L((0, 700), (0, 520))]),
    '"': (140, [L((0, 700), (0, 520)), L((140, 700), (140, 520))]),
    '(': (130, [A(300, 300, 300, 470, 126, 234)]),
    ')': (130, [A(-170, 300, 300, 470, 54, -54)]),
    '/': (360, [L((0, -80), (360, 760))]),
    '?': (400, [A(200, 520, 200, 180, 165, -80), L((235, 343), (200, 300), (200, 200)), D(200, 0)]),
    '!': (0, [L((0, 700), (0, 220)), D(0, 0)]),
    '+': (400, [L((0, 300), (400, 300)), L((200, 100), (200, 500))]),
    '=': (380, [L((0, 390), (380, 390)), L((0, 210), (380, 210))]),
    '_': (450, [L((0, -120), (450, -120))]),
    '%': (520, [circle(90, 590, 90, 110), L((470, 700), (50, 0)), circle(430, 110, 90, 110)]),
    '&': (540, [A(190, 560, 140, 140, -40, 220), L((80, 470), (540, 0)), A(220, 200, 200, 200, 120, 330)]),
}


def stroke_polyline(pts):
    polys = []
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        dx, dy = x1 - x0, y1 - y0
        length = math.hypot(dx, dy)
        if length == 0:
            continue
        nx, ny = -dy / length * W / 2, dx / length * W / 2
        polys.append([(x0 + nx, y0 + ny), (x1 + nx, y1 + ny), (x1 - nx, y1 - ny), (x0 - nx, y0 - ny)])
    for x, y in pts:
        polys.append(disc(x, y))
    return polys


def disc(x, y, r=W / 2, n=28):
    return [(x + r * math.cos(2 * math.pi * k / n), y + r * math.sin(2 * math.pi * k / n)) for k in range(n)]


def stroke_arc(cx, cy, rx, ry, a0, a1):
    steps = max(12, int(abs(a1 - a0) / 4))
    pts, normals = [], []
    for k in range(steps + 1):
        t = math.radians(a0 + (a1 - a0) * k / steps)
        x, y = cx + rx * math.cos(t), cy + ry * math.sin(t)
        nx, ny = ry * math.cos(t), rx * math.sin(t)  # outward normal of an ellipse
        n = math.hypot(nx, ny) or 1
        pts.append((x, y))
        normals.append((nx / n, ny / n))
    full = abs(abs(a1 - a0) - 360) < 1e-6
    outer = [(x + nx * W / 2, y + ny * W / 2) for (x, y), (nx, ny) in zip(pts, normals)]
    inner = [(x - nx * W / 2, y - ny * W / 2) for (x, y), (nx, ny) in zip(pts, normals)]
    if full:
        # Ring: outer contour and inner contour in opposite directions.
        return [outer[:-1], list(reversed(inner[:-1]))], True
    polys = [outer + list(reversed(inner)), disc(*pts[0]), disc(*pts[-1])]
    return polys, False


def area(poly):
    return sum(x0 * y1 - x1 * y0 for (x0, y0), (x1, y1) in zip(poly, poly[1:] + poly[:1])) / 2


def clockwise(poly):
    return poly if area(poly) < 0 else list(reversed(poly))


def counter(poly):
    return poly if area(poly) > 0 else list(reversed(poly))


def build_glyph(width, strokes):
    pen = TTGlyphPen(None)
    contours = []
    for kind, data in strokes:
        if kind == 'L':
            contours += [clockwise(p) for p in stroke_polyline([(x + M + W / 2, y) for x, y in data])]
        elif kind == 'D':
            x, y = data
            contours.append(clockwise(disc(x + M + W / 2, y, W / 2 + 6)))
        else:
            cx, cy, rx, ry, a0, a1 = data
            polys, ring = stroke_arc(cx + M + W / 2, cy, rx, ry, a0, a1)
            if ring:
                contours += [clockwise(polys[0]), counter(polys[1])]
            else:
                contours += [clockwise(p) for p in polys]
    for poly in contours:
        pts = [(round(x), round(y)) for x, y in poly]
        pen.moveTo(pts[0])
        for p in pts[1:]:
            pen.lineTo(p)
        pen.closePath()
    glyph = pen.glyph()
    if glyph.numberOfContours > 0:
        glyph.flags[0] |= 0x40  # OVERLAP_SIMPLE: contours overlap on purpose
    return glyph, width + 2 * M + W


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    names = {ch: (f'uni{ord(ch):04X}' if not ch.isalnum() else ch) for ch in G}
    order = ['.notdef', 'space'] + [names[ch] for ch in G]
    fb = FontBuilder(UPM, isTTF=True)
    fb.setupGlyphOrder(order)
    cmap = {ord(' '): 'space'}
    cmap.update({ord(ch): names[ch] for ch in G})
    fb.setupCharacterMap(cmap)
    glyphs, metrics = {}, {}
    empty = TTGlyphPen(None).glyph()
    notdef_pen = TTGlyphPen(None)
    for poly in ([(60, 0), (60, 700), (440, 700), (440, 0)], [(120, 60), (380, 60), (380, 640), (120, 640)]):
        notdef_pen.moveTo(poly[0])
        for p in poly[1:]:
            notdef_pen.lineTo(p)
        notdef_pen.closePath()
    glyphs['.notdef'] = notdef_pen.glyph()
    metrics['.notdef'] = (500, 60)
    glyphs['space'] = empty
    metrics['space'] = (280, 0)
    for ch, (width, strokes) in G.items():
        glyph, adv = build_glyph(width, strokes)
        glyphs[names[ch]] = glyph
        metrics[names[ch]] = (adv, 0)
    fb.setupGlyf(glyphs)
    for name, glyph in glyphs.items():
        glyph.recalcBounds(fb.font['glyf'])
        if name in metrics and hasattr(glyph, 'xMin') and glyph.numberOfContours:
            metrics[name] = (metrics[name][0], glyph.xMin)
    fb.setupHorizontalMetrics(metrics)
    fb.setupHorizontalHeader(ascent=ASC + 120, descent=DESC - 60)
    fb.setupNameTable({
        'familyName': 'ShieldGraph Plot',
        'styleName': 'Regular',
        'uniqueFontIdentifier': 'ShieldGraphPlot-Regular-1.0',
        'fullName': 'ShieldGraph Plot',
        'psName': 'ShieldGraphPlot-Regular',
        'version': 'Version 1.000',
        'licenseDescription': 'MIT License. Drawn from scratch for ShieldGraph.',
    })
    fb.setupOS2(sTypoAscender=ASC + 120, sTypoDescender=DESC - 60, sTypoLineGap=0, usWinAscent=ASC + 140, usWinDescent=abs(DESC) + 80, sxHeight=XH, sCapHeight=CAP, achVendID='SGPH', fsType=0, usWeightClass=600)
    fb.setupPost()
    fb.setupHead(unitsPerEm=UPM)
    fb.font.flavor = 'woff2'
    out = os.path.join(root, 'fonts', 'shieldgraph-plot.woff2')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    fb.save(out)
    print(out, os.path.getsize(out), 'bytes,', len(G), 'glyphs')


if __name__ == '__main__':
    main()
