"""Builds internal/server/web/regions/<CC>.json, the provinces of each country
for the attackers map, in the projection of world.js.

Source: Natural Earth 1:10m admin 1 states and provinces, public domain, pinned to v5.1.2:
  curl -LO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/ne_10m_admin_1_states_provinces.geojson
  python3 tools/worldmap/mkregions.py ne_10m_admin_1_states_provinces.geojson internal/server/web/regions 0.06

Each file: {"cc": "DE", "regions": [{"id", "en", "de", "at": [x, y], "d": path}]}.
"""
import json, sys, os, math
src, out, eps = sys.argv[1], sys.argv[2], float(sys.argv[3])
W, TOP, BOTTOM = 1000, 84, -58
H = W * (TOP - BOTTOM) / 360
def proj(lon, lat):
    return (lon + 180) / 360 * W, (TOP - lat) / (TOP - BOTTOM) * H
def dp(pts, eps):
    # Douglas-Peucker without recursion; long coastlines would hit the limit
    if len(pts) < 3: return pts
    keep = [False] * len(pts); keep[0] = keep[-1] = True
    stack = [(0, len(pts) - 1)]
    while stack:
        i0, i1 = stack.pop()
        a, b = pts[i0], pts[i1]
        dx, dy = b[0]-a[0], b[1]-a[1]; n = math.hypot(dx, dy)
        im, dm = -1, -1
        for k in range(i0 + 1, i1):
            p = pts[k]
            dd = abs(dy*p[0]-dx*p[1]+b[0]*a[1]-b[1]*a[0])/n if n > 1e-9 else math.hypot(p[0]-a[0], p[1]-a[1])
            if dd > dm: im, dm = k, dd
        if dm > eps:
            keep[im] = True
            stack += [(i0, im), (im, i1)]
    return [p for p, k in zip(pts, keep) if k]
by = {}
for f in json.load(open(src))["features"]:
    p = f["properties"]
    cc = p.get("iso_a2")
    if not cc or len(cc) != 2 or cc == "AQ" or not f["geometry"]: continue
    g = f["geometry"]
    polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
    parts = []
    for poly in polys:
        ring = [proj(x, y) for x, y in poly[0]]
        xs = [q[0] for q in ring]; ys = [q[1] for q in ring]
        if max(xs) - min(xs) < eps * 2 and max(ys) - min(ys) < eps * 2: continue
        r = dp(ring, eps)
        if len(r) < 4: continue
        parts.append("M" + "L".join("%g,%g" % (round(x, 2), round(y, 2)) for x, y in r[:-1]) + "Z")
    if not parts: continue
    lx, ly = proj(p["longitude"], p["latitude"]) if p.get("longitude") is not None else (None, None)
    rid = p.get("iso_3166_2") or p.get("adm1_code")
    if not rid or rid.endswith("~") or rid.endswith("-"): rid = p.get("adm1_code")
    by.setdefault(cc, []).append({"id": rid, "en": p.get("name_en") or p.get("name") or rid, "de": p.get("name_de") or p.get("name_en") or p.get("name") or rid,
        "at": [round(lx, 2), round(ly, 2)] if lx is not None else None, "d": "".join(parts)})
os.makedirs(out, exist_ok=True)
for name in os.listdir(out):
    if name.endswith(".json"): os.remove(os.path.join(out, name))
total = 0
for cc, regions in sorted(by.items()):
    if len(regions) < 2: continue
    seen = {}
    for r in regions:
        # ids are unique per file
        if r["id"] in seen: seen[r["id"]] += 1; r["id"] += "#" + str(seen[r["id"]])
        else: seen[r["id"]] = 0
    regions.sort(key=lambda r: r["id"])
    js = json.dumps({"cc": cc, "regions": regions}, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    open(os.path.join(out, cc + ".json"), "w", encoding="utf-8").write(js + "\n")
    total += len(js.encode())
print(len([c for c in by if len(by[c]) > 1]), "countries,", total, "bytes")
