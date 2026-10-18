"""Builds internal/server/web/world.js, the country outlines of the attackers map.

Source: Natural Earth 1:50m admin 0 countries, public domain, pinned to v5.1.2:
  curl -LO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/ne_50m_admin_0_countries.geojson
  python3 tools/worldmap/mkworld.py ne_50m_admin_0_countries.geojson internal/server/web/world.js 0.6
"""
import json, sys, math
src, out, eps = sys.argv[1], sys.argv[2], float(sys.argv[3])
d = json.load(open(src))
W, TOP, BOTTOM = 1000, 84, -58
H = W * (TOP - BOTTOM) / 360
def proj(lon, lat):
    # equirectangular from 84 N to 58 S (Antarctica left out)
    return (lon + 180) / 360 * W, (TOP - lat) / (TOP - BOTTOM) * H
def dp(pts, eps):
    if len(pts) < 3: return pts
    a, b = pts[0], pts[-1]
    dx, dy = b[0]-a[0], b[1]-a[1]; n = math.hypot(dx, dy) or 1e-9
    i, dm = 0, -1
    for k in range(1, len(pts)-1):
        p = pts[k]
        dd = abs(dy*p[0]-dx*p[1]+b[0]*a[1]-b[1]*a[0])/n if n > 1e-9 else math.hypot(p[0]-a[0], p[1]-a[1])
        if dd > dm: i, dm = k, dd
    if dm > eps:
        return dp(pts[:i+1], eps)[:-1] + dp(pts[i:], eps)
    return [a, b]
res, dots = {}, {}
for f in d["features"]:
    p = f["properties"]
    cc = p.get("ISO_A2_EH") or p.get("ISO_A2")
    if not cc or cc == "-99" or cc == "AQ": continue
    g = f["geometry"]
    polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
    parts = []
    big = max(polys, key=lambda pl: len(pl[0]))[0]
    xs = [proj(x, y) for x, y in big]
    dots[cc] = [round((min(q[0] for q in xs) + max(q[0] for q in xs)) / 2, 1), round((min(q[1] for q in xs) + max(q[1] for q in xs)) / 2, 1)]
    for poly in polys:
        ring = [proj(x, y) for x, y in poly[0]]
        r = dp(ring, eps)
        if len(r) < 4:
            xs=[q[0] for q in ring]; ys=[q[1] for q in ring]
            if max(xs)-min(xs) < 1.2 and max(ys)-min(ys) < 1.2: continue
        s = "M" + "L".join("%g,%g" % (round(x, 1), round(y, 1)) for x, y in r) + "Z"
        parts.append(s)
    if parts:
        res[cc] = res.get(cc, "") + "".join(parts)
js = ("// Country outlines and centres from Natural Earth 1:50m (public domain), simplified.\n"
      "// Built by tools/worldmap/mkworld.py (equirectangular, %d x %g, 84 N to 58 S).\n" % (W, H) +
      "window.VIGIL_WORLD={w:%d,h:%g,paths:" % (W, round(H, 1)) + json.dumps(res, separators=(",", ":"), sort_keys=True) +
      ",dots:" + json.dumps(dots, separators=(",", ":"), sort_keys=True) + "};\n")
open(out, "w").write(js)
print(len(res), len(js))
