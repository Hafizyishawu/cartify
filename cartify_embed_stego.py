
import json
from PIL import Image

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
