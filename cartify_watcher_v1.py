import os
import time
import hashlib
import imagehash
import json
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
from datetime import datetime
from shutil import copyfile
from pathlib import Path
from fpdf import FPDF
import imageio

WATCH_FOLDER = "/Users/hafizyishawu/Desktop/art_exports"
EXPORT_FOLDER = os.path.join(WATCH_FOLDER, "exports")
TEMPLATE_IMAGE_PATH = "template/Cartify_Certificate_Poster_Updated_Final2.png"
TEMPLATE_GIF_PATH = "template/Cartify_Fingerprint_Glow_4s.gif"
FINGERPRINT_LOG = os.path.join(WATCH_FOLDER, "fingerprint_log.csv")

os.makedirs(EXPORT_FOLDER, exist_ok=True)
processed = set()

print("[👁️] Watching folder:", WATCH_FOLDER)

def is_file_ready(filepath):
    initial = -1
    while True:
        size = os.path.getsize(filepath)
        if size == initial:
            return True
        initial = size
        time.sleep(0.5)

def generate_hashes(image_path):
    with Image.open(image_path) as img:
        sha256 = hashlib.sha256(img.tobytes()).hexdigest()
        phash = str(imagehash.phash(img))
        Author = "Abdulhafiz Idowu Yishawu"
    return sha256, phash, Author

def embed_metadata(image_path, title, author):
    with Image.open(image_path) as img:
        meta = PngImagePlugin.PngInfo()
        meta.add_text("Title", title)
        meta.add_text("Author", author)
        meta.add_text("Copyright", f"© {author}")
        img.save(image_path, pnginfo=meta)

def write_fingerprint_json(export_path, sha256, phash, author):
    data = {
        "sha256": sha256,
        "phash": phash,
        "timestamp": datetime.utcnow().isoformat(),
        "author": author
    }
    with open(os.path.join(export_path, "fingerprint.json"), "w") as f:
        json.dump(data, f, indent=4)

def append_to_log(sha256, phash, Author):
    with open(FINGERPRINT_LOG, "a") as f:
        f.write(f"{sha256},{phash},{Author},{datetime.utcnow().isoformat()}\n")

def embed_stego_metadata(image_path, metadata, output_path):
    metadata_str = json.dumps(metadata)
    binary_data = ''.join(format(ord(c), '08b') for c in metadata_str)
    eof_marker = '1111111111111110'
    binary_data += eof_marker

    image = Image.open(image_path).convert("RGB")
    pixels = list(image.getdata())

    if len(binary_data) > len(pixels) * 3:
        raise ValueError("Not enough pixels to embed the data.")

    new_pixels = []
    bit_idx = 0

    for pixel in pixels:
        r, g, b = pixel
        if bit_idx < len(binary_data):
            r = (r & ~1) | int(binary_data[bit_idx])
            bit_idx += 1
        if bit_idx < len(binary_data):
            g = (g & ~1) | int(binary_data[bit_idx])
            bit_idx += 1
        if bit_idx < len(binary_data):
            b = (b & ~1) | int(binary_data[bit_idx])
            bit_idx += 1
        new_pixels.append((r, g, b))

    new_pixels += pixels[len(new_pixels):]
    stego_image = Image.new("RGB", image.size)
    stego_image.putdata(new_pixels)
    stego_image.save(output_path)

    return {
        "status": "success",
        "bits_embedded": len(binary_data),
        "image_size": image.size,
        "output_path": output_path
    }

def generate_pdf_certificate(cert_image_path, pdf_path):
    pdf = FPDF()
    pdf.add_page()
    pdf.image(cert_image_path, x=10, y=10, w=190)
    pdf.output(pdf_path)

def generate_gif_certificate(poster_path, gif_template_path, gif_output_path):
    base = Image.open(poster_path).convert("RGBA")
    frames = imageio.mimread(gif_template_path)
    gif_frames = []
    for frame in frames:
        glow = Image.fromarray(frame).resize((100, 100)).convert("RGBA")
        poster_with_glow = base.copy()
        poster_with_glow.paste(glow, (600, 70), glow)
        gif_frames.append(poster_with_glow)
    gif_frames[0].save(gif_output_path, save_all=True, append_images=gif_frames[1:], duration=100, loop=0)

def generate_certificates(export_path, base_name, preview_path, sha256, phash):
    poster = Image.open(TEMPLATE_IMAGE_PATH).convert("RGBA")
    draw = ImageDraw.Draw(poster)
    try:
        font_meta = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 24)
    except:
        font_meta = ImageFont.load_default()

    # Inject preview
    preview = Image.open(preview_path).resize((500, 600)).convert("RGBA")
    poster.paste(preview, (100, 300))

    # Inject metadata
    meta_x, meta_y = 650, 300
    line_gap = 38
    draw.text((meta_x, meta_y), f"Title: {base_name}", font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), "Creator: Abdulhafiz Idowu Yishawu", font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), "SHA-256:", font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), sha256[:32], font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), sha256[32:], font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), f"pHash: {phash}", font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), f"Timestamp (UTC):", font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), datetime.utcnow().isoformat(), font=font_meta, fill="black")

    cert_png = os.path.join(export_path, f"{base_name}_certificate.png")
    cert_pdf = os.path.join(export_path, f"{base_name}_certificate.pdf")
    cert_gif = os.path.join(export_path, f"{base_name}_certificate.gif")
    poster.save(cert_png)
    generate_pdf_certificate(cert_png, cert_pdf)
    generate_gif_certificate(cert_png, TEMPLATE_GIF_PATH, cert_gif)

def process_file(file_path):
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    export_path = os.path.join(EXPORT_FOLDER, base_name)
    os.makedirs(export_path, exist_ok=True)

    exported_image_path = os.path.join(export_path, f"{base_name}.png")
    if os.path.exists(exported_image_path):
        print("[⚠️] Already processed:", exported_image_path)
        return

    if not is_file_ready(file_path):
        return

    exported_image_path = os.path.join(export_path, f"{base_name}.png")
    copyfile(file_path, exported_image_path)

    sha256, phash, Author = generate_hashes(exported_image_path)
    print("[🔍] SHA-256:", sha256)
    print("[🧠] pHash:", phash)
    print("[@] Author:", Author)
    embed_metadata(exported_image_path, base_name, "Abdulhafiz Idowu Yishawu")
    stego_output_path = os.path.join(export_path, f"{base_name}_stego.png")
    embed_result = embed_stego_metadata(exported_image_path, {
        "Title": base_name,
        "Creator": Author,
        "SHA-256": sha256,
        "pHash": phash,
        "Timestamp": datetime.utcnow().isoformat()
    }, stego_output_path)

    print("[🧬] Stego Embed:", embed_result["status"])
    print("[📦] Saved stego image:", stego_output_path)
    write_fingerprint_json(export_path, sha256, phash, Author)
    append_to_log(sha256, phash, Author)
    generate_certificates(export_path, base_name, exported_image_path, sha256, phash)

    print("[✅] Fingerprinted, certified, and exported:", exported_image_path)

def watcher_loop():
    while True:
        for file in os.listdir(WATCH_FOLDER):
            if file.startswith("OXXI") and file.endswith(".png"):
                full_path = os.path.join(WATCH_FOLDER, file)
                if full_path not in processed:
                    process_file(full_path)
                    processed.add(full_path)
        time.sleep(3)

watcher_loop()
