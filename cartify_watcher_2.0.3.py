
import os
import time
import hashlib
import imagehash
import json
import re
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
from drive_upload import upload_file_to_drive
from datetime import datetime
from shutil import copyfile, move
import zipfile
import imageio
from fpdf import FPDF

CONFIG_FILE = 'config.json'
PROCESSED_LOG_FILE = 'processed_files.json'
ORIGINALS_SUBFOLDER = 'originals'

def sanitize_filename(text):
    return re.sub(r'[^\w\-_\.]', '_', text)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        return config.get('watch_folder'), config.get('export_folder')
    else:
        folder = input("Enter full path to folder to watch for art files: ").strip()
        export = os.path.join(folder, "exports")
        os.makedirs(export, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump({"watch_folder": folder, "export_folder": export}, f)
        return folder, export

def load_processed_files():
    if os.path.exists(PROCESSED_LOG_FILE):
        with open(PROCESSED_LOG_FILE, 'r') as f:
            try:
                data = json.load(f)
                # Migrate old entries that don't have required keys
                cleaned = [entry for entry in data if isinstance(entry, dict) and 'path' in entry and 'sha256' in entry]
                return cleaned
            except json.JSONDecodeError:
                return []
    return []

def save_processed_files(logs):
    with open(PROCESSED_LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

def prompt_art_metadata(base_name):
    print(f"[🖼️] Preparing to process: {base_name}")
    author = input("Enter the author's full name (or leave blank for 'Anonymous'): ").strip() or "Anonymous"
    title = input("Enter the artwork title (or leave blank for 'Untitled'): ").strip() or "Untitled"
    return author, sanitize_filename(title)

def is_file_ready(filepath):
    initial = -1
    while True:
        try:
            size = os.path.getsize(filepath)
            if size == initial:
                return True
            initial = size
            time.sleep(0.5)
        except FileNotFoundError:
            return False

def generate_hashes(image_path):
    with Image.open(image_path) as img:
        sha256 = hashlib.sha256(img.tobytes()).hexdigest()
        phash = str(imagehash.phash(img))
    return sha256, phash

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
    return {"status": "success", "bits_embedded": len(binary_data)}

def generate_certificates(export_path, title, preview_path, sha256, phash, author):
    TEMPLATE_IMAGE_PATH = "template/Cartify_Certificate_Poster_Updated_Final2.png"
    TEMPLATE_GIF_PATH = "template/Cartify_Fingerprint_Glow_4s.gif"

    poster = Image.open(TEMPLATE_IMAGE_PATH).convert("RGBA")
    draw = ImageDraw.Draw(poster)
    try:
        font_meta = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 24)
    except:
        font_meta = ImageFont.load_default()

    preview = Image.open(preview_path).resize((500, 600)).convert("RGBA")
    poster.paste(preview, (100, 300))

    meta_x, meta_y = 650, 300
    line_gap = 38
    draw.text((meta_x, meta_y), f"Title: {title}", font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), f"Creator: {author}", font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), "SHA-256:", font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), sha256[:32], font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), sha256[32:], font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), f"pHash: {phash}", font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), "Timestamp (UTC):", font=font_meta, fill="black"); meta_y += line_gap
    draw.text((meta_x, meta_y), datetime.utcnow().isoformat(), font=font_meta, fill="black")

    cert_png = os.path.join(export_path, f"{title}_certificate.png")
    cert_pdf = os.path.join(export_path, f"{title}_certificate.pdf")
    cert_gif = os.path.join(export_path, f"{title}_certificate.gif")
    poster.save(cert_png)

    pdf = FPDF(); pdf.add_page(); pdf.image(cert_png, x=10, y=10, w=190); pdf.output(cert_pdf)

    base = Image.open(cert_png).convert("RGBA")
    frames = imageio.mimread(TEMPLATE_GIF_PATH)
    gif_frames = []
    for frame in frames:
        glow = Image.fromarray(frame).resize((100, 100)).convert("RGBA")
        poster_with_glow = base.copy()
        poster_with_glow.paste(glow, (600, 70), glow)
        gif_frames.append(poster_with_glow)
    gif_frames[0].save(cert_gif, save_all=True, append_images=gif_frames[1:], duration=100, loop=0)

def zip_certified_package(export_path, title):
    zip_path = os.path.join(export_path, f"{title}_certified_bundle.zip")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for filename in [
            f"{title}_stego.png",
            f"{title}_certificate.pdf",
            f"{title}_certificate.gif",
            "fingerprint.json"
        ]:
            file_path = os.path.join(export_path, filename)
            if os.path.exists(file_path):
                zipf.write(file_path, arcname=filename)
    return zip_path

def main():
    watch_folder, export_folder = load_config()
    print(f"[👁️] Watching folder: {watch_folder}")

    processed_files = load_processed_files()
    processed_paths = set(p["path"] for p in processed_files)
    processed_hashes = set(p["sha256"] for p in processed_files)

    if not os.path.exists(os.path.join(watch_folder, ORIGINALS_SUBFOLDER)):
        os.makedirs(os.path.join(watch_folder, ORIGINALS_SUBFOLDER))

    while True:
        for file in os.listdir(watch_folder):
            full_path = os.path.join(watch_folder, file)
            if not file.lower().startswith("cart_") or not file.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".webp", ".jfif", ".pjpeg", ".pjp")):
                continue
            if full_path in processed_paths:
                continue

            if not is_file_ready(full_path):
                continue

            try:
                sha256, phash = generate_hashes(full_path)
            except Exception as e:
                print(f"[!] Could not open or hash file: {file}")
                continue

            if sha256 in processed_hashes:
                if not any(p["path"] == full_path for p in processed_files):
                    processed_files.append({"path": full_path, "sha256": sha256})
                    save_processed_files(processed_files)
                move(full_path, os.path.join(watch_folder, ORIGINALS_SUBFOLDER, file))
                continue

            base_name = os.path.splitext(file)[0]
            author, title = prompt_art_metadata(base_name)
            export_path = os.path.join(export_folder, title)
            if os.path.exists(export_path):
                confirm = input(f"[!] Warning: A folder for '{title}' already exists. Overwrite? (y/n): ").strip().lower()
                if confirm != 'y':
                    continue

            os.makedirs(export_path, exist_ok=True)
            exported_image_path = os.path.join(export_path, f"{title}.png")
            copyfile(full_path, exported_image_path)

            print("[🔍] SHA-256:", sha256)
            print("[🧠] pHash:", phash)
            print(f"[✍️] Author: {author}")

            embed_metadata(exported_image_path, title, author)
            stego_output_path = os.path.join(export_path, f"{title}_stego.png")
            embed_result = embed_stego_metadata(exported_image_path, {
                "Title": title,
                "Creator": author,
                "SHA-256": sha256,
                "pHash": phash,
                "Timestamp": datetime.utcnow().isoformat()
            }, stego_output_path)
            print("[🧬] Stego Embed:", embed_result["status"])

            write_fingerprint_json(export_path, sha256, phash, author)
            generate_certificates(export_path, title, exported_image_path, sha256, phash, author)

            zip_path = zip_certified_package(export_path, title)
            drive_link = upload_file_to_drive(zip_path)
            print("[☁️] Uploaded to Google Drive:", drive_link)
            print("[✅] Complete:", exported_image_path)

            processed_files.append({"path": full_path, "sha256": sha256})
            save_processed_files(processed_files)

            move(full_path, os.path.join(watch_folder, ORIGINALS_SUBFOLDER, file))

        time.sleep(3)

if __name__ == "__main__":
    main()
