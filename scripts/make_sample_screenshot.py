"""Regenerate sample_data/sms_screenshot.png (synthetic SMS screenshot used for the OCR demo)."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parents[1] / "sample_data" / "sms_screenshot.png"
LINES = ["Messages  -  +971 50 123 4567", "",
         "FINAL NOTICE: Your Aramex parcel AE-77812",
         "will be returned today. Pay the customs fee",
         "of 14 AED immediately at",
         "http://aramex-delivery-ae.top/pay",
         "Do not share this message with anyone."]
try:
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 30)
except OSError:
    font = ImageFont.load_default()
img = Image.new("RGB", (900, 420), "white")
d = ImageDraw.Draw(img)
d.rounded_rectangle((30, 90, 870, 390), 24, fill=(233, 236, 240))
y = 30
for i, line in enumerate(LINES):
    d.text((50, y), line, fill=(20, 30, 40), font=font)
    y += 52 if i else 60
img.save(OUT)
print(OUT)
