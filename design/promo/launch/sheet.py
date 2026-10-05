# Tile stills into a contact sheet with their times: python3 sheet.py OUT COLS FILE...
import re, sys
from PIL import Image, ImageDraw, ImageFont

out, cols, files = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
tw = 480
th = tw * 1080 // 1920
rows = (len(files) + cols - 1) // cols
sheet = Image.new('RGB', (cols * (tw + 4) + 4, rows * (th + 4) + 4), (40, 40, 40))
try:
    font = ImageFont.truetype('/System/Library/Fonts/SFNSMono.ttf', 18)
except Exception:
    font = ImageFont.load_default()
for i, f in enumerate(files):
    im = Image.open(f).convert('RGB').resize((tw, th), Image.LANCZOS)
    x, y = 4 + (i % cols) * (tw + 4), 4 + (i // cols) * (th + 4)
    sheet.paste(im, (x, y))
    m = re.search(r't0*([\d.]+)\.(?:png|jpg)$', f)
    d = ImageDraw.Draw(sheet)
    label = (m.group(1) if m else str(i)) + 's'
    d.rectangle([x, y, x + 12 * len(label) + 8, y + 24], fill=(0, 0, 0))
    d.text((x + 4, y + 2), label, fill=(255, 255, 0), font=font)
sheet.save(out, quality=88) if out.endswith('.jpg') else sheet.save(out)
print(out)
