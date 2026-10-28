#!/usr/bin/env python3
# Writes web/world.json, the Map tab's countries and capitals, from Natural Earth's 1:110m
# countries (public domain) and logguard's own capitals (../logguard/src/capitals.rs, the TUI's):
#
#   curl -fLO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson
#   python3 scripts/world-map.py ne_110m_admin_0_countries.geojson ../logguard/src/capitals.rs web/world.json
#
# The file: {"src": ..., "c": [[iso, name, [ring, ...]], ...], "cap": {iso: [lat, lon]}}. A ring is
# [lon0*10, lat0*10, dlon*10, dlat*10, ...]: tenths of a degree, steps after the first point.
# Outer rings only (holes are lakes at this scale); Antarctica left out, as on the TUI's map.
import json, re, sys
ne, capitals_rs, out = sys.argv[1:4]
src = json.load(open(ne))
countries, points = [], 0
for f in src["features"]:
    p = f["properties"]
    iso = p.get("ISO_A2_EH") or p.get("ISO_A2")
    if not iso or len(iso) != 2 or not iso.isalpha():
        iso = ""
    if iso == "AQ":
        continue
    name = p.get("NAME_EN") or p.get("NAME")
    g = f["geometry"]
    polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
    rings = []
    for poly in polys:
        for ring in poly[:1]:  # outer rings: holes are lakes at this scale
            pts, last = [], None
            for lon, lat in ring:
                q = (round(lon * 10), round(lat * 10))
                if q != last:
                    pts.append(q); last = q
            if len(pts) < 4:
                continue
            flat = [pts[0][0], pts[0][1]]
            for a, b in zip(pts, pts[1:]):
                flat += [b[0] - a[0], b[1] - a[1]]
            rings.append(flat); points += len(pts)
    if rings:
        countries.append([iso, name, rings])
caps = {c: [float(a), float(b)] for c, a, b in re.findall(r'\("([A-Z]{2})", (-?[\d.]+), (-?[\d.]+)\)', open(capitals_rs).read())}
doc = {"src": "Made with Natural Earth (public domain), 1:110m countries; capitals as in logguard's src/capitals.rs", "c": countries, "cap": caps}
open(out, "w").write(json.dumps(doc, separators=(",", ":"), ensure_ascii=False))
print(len(countries), "countries,", points, "points,", len(caps), "capitals;", sum(1 for c in countries if not c[0]), "without a code:", [c[1] for c in countries if not c[0]])
