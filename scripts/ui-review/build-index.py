#!/usr/bin/env python3
"""Write the side-by-side review page of a screenshot tour.

Usage: build-index.py OUT_DIR

Reads OUT_DIR/rows.json and writes OUT_DIR/index.html: one row per view, the mockup
frame on the left (mockups/NAME), the screenshots on the right (shots/NAME), and a short
note under the pair. The page has no external resources, references the images by
relative path, and follows the light or dark setting of the system.

rows.json:
  {"title": "...", "intro": ["paragraph", ...],
   "sections": [{"title": "...", "rows": [
      {"title": "...", "mockups": ["connect-12a.png"], "shots": ["share-section.png"],
       "note": "..."}]}]}
A row without mockups says "No mockup frame"; a name that is missing on disk is listed
as missing, so the page never shows a broken image.
"""
import html
import json
import os
import sys

STYLE = """
:root { color-scheme: light dark; --bg: #f6f6f7; --card: #ffffff; --text: #1d1d1f;
  --muted: #5f6368; --line: #d9d9de; --warn: #9a5b00; --accent: #0a66d9; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #161618; --card: #232326; --text: #ececf0; --muted: #a8a8b0;
    --line: #3a3a40; --warn: #f0b35a; --accent: #6aa8ff; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 2300px; margin: 0 auto; padding: 24px; }
h1 { font-size: 26px; margin: 0 0 8px; }
h2 { font-size: 20px; margin: 36px 0 12px; padding-top: 12px; border-top: 1px solid var(--line); }
h3 { font-size: 16px; margin: 0 0 10px; }
p { margin: 6px 0; max-width: 1100px; }
a { color: var(--accent); }
nav ul { columns: 2; max-width: 1100px; padding-left: 18px; }
.row { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 16px; margin: 0 0 18px; }
.pair { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 16px;
  align-items: start; }
.col { display: flex; flex-direction: column; gap: 10px; min-width: 0; }
.label { font-size: 12px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase;
  color: var(--muted); }
figure { margin: 0; }
figure img { display: block; width: 100%; max-width: 1100px; height: auto;
  border: 1px solid var(--line); border-radius: 6px; background: #fff; }
figcaption { font-size: 12px; color: var(--muted); margin-top: 4px; word-break: break-all; }
.none { color: var(--muted); font-style: italic; padding: 12px; border: 1px dashed var(--line);
  border-radius: 6px; }
.missing { color: var(--warn); }
.note { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--line); }
@media (max-width: 900px) { .pair { grid-template-columns: 1fr; } }
"""


def figure(folder, name, out):
    path = os.path.join(out, folder, name)
    rel = f"{folder}/{name}"
    if not os.path.exists(path):
        return f'<p class="missing">Missing: {html.escape(rel)}</p>'
    return (f'<figure><a href="{html.escape(rel)}"><img loading="lazy" src="{html.escape(rel)}" '
            f'alt="{html.escape(name)}"></a><figcaption>{html.escape(rel)}</figcaption></figure>')


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    with open(os.path.join(out, "rows.json"), encoding="utf-8") as f:
        data = json.load(f)
    parts = ["<!DOCTYPE html>", '<html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             f"<title>{html.escape(data['title'])}</title><style>{STYLE}</style></head><body><main>",
             f"<h1>{html.escape(data['title'])}</h1>"]
    for paragraph in data.get("intro", []):
        parts.append(f"<p>{paragraph}</p>")
    parts.append("<nav><ul>")
    for i, section in enumerate(data["sections"]):
        parts.append(f'<li><a href="#s{i}">{html.escape(section["title"])}</a></li>')
    parts.append("</ul></nav>")
    rows = shots = 0
    for i, section in enumerate(data["sections"]):
        parts.append(f'<h2 id="s{i}">{html.escape(section["title"])}</h2>')
        for row in section["rows"]:
            rows += 1
            parts.append(f'<section class="row"><h3>{html.escape(row["title"])}</h3><div class="pair">')
            parts.append('<div class="col"><div class="label">Mockup</div>')
            if row.get("mockups"):
                parts.extend(figure("mockups", name, out) for name in row["mockups"])
            else:
                parts.append('<div class="none">No mockup frame for this state.</div>')
            parts.append('</div><div class="col"><div class="label">Screenshot (Linux, Xvfb)</div>')
            if row.get("shots"):
                shots += len(row["shots"])
                parts.extend(figure("shots", name, out) for name in row["shots"])
            else:
                parts.append('<div class="none">Not captured.</div>')
            parts.append("</div></div>")
            if row.get("note"):
                parts.append(f'<div class="note">{html.escape(row["note"])}</div>')
            parts.append("</section>")
    parts.append("</main></body></html>")
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    print(f"index.html: {rows} rows, {shots} screenshots")


if __name__ == "__main__":
    main()
