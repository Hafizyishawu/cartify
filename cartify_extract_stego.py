
import json
from PIL import Image
import sys

def extract_stego_metadata_optimized(image_path):
    image = Image.open(image_path).convert("RGB")
    pixels = list(image.getdata())

    binary_data = ""
    eof_marker = "1111111111111110"
    marker_len = len(eof_marker)

    for pixel in pixels:
        for color in pixel:
            binary_data += str(color & 1)
            if binary_data[-marker_len:] == eof_marker:
                binary_data = binary_data[:-marker_len]
                metadata_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
                metadata_str = ''.join([chr(int(b, 2)) for b in metadata_bytes])
                print("Raw extracted sting:")
                print(metadata_str)
                try:
                    return {"status": "success", "metadata": json.loads(metadata_str)}
                except json.JSONDecodeError:
                    return {"status": "error", "message": "Failed to decode metadata JSON."}

    return {"status": "error", "message": "EOF marker not found."}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cartify_extract_stego.py <path_to_image>")
    else:
        image_path = sys.argv[1]
        result = extract_stego_metadata_optimized(image_path)
        print(result)

