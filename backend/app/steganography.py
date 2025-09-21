# Core logic for hiding data

from PIL import Image
import os

def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def _bits_to_bytes(bits):
    out = bytearray()
    cur = 0
    count = 0
    for b in bits:
        cur = (cur << 1) | (b & 1)
        count += 1
        if count == 8:
            out.append(cur)
            cur = 0
            count = 0
    if count != 0:
        cur = cur << (8 - count)
        out.append(cur)
    return bytes(out)

def embed_message_in_image(input_path: str, payload: bytes, output_path: str):
    """Embed payload bytes into an image using simple RGB LSB. Stores a 32-bit big-endian length prefix.
    Always writes a PNG to preserve exact pixel data.
    """
    with Image.open(input_path) as img:
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        has_alpha = img.mode == 'RGBA'
        pixels = list(img.getdata())

    # Calculate capacity (3 channels per pixel used: R,G,B)
    total_channels = len(pixels) * 3
    required_bits = (4 + len(payload)) * 8  # 4 length bytes + payload
    if required_bits > total_channels:
        raise ValueError('Cover image too small for payload')

    length_prefix = len(payload).to_bytes(4, 'big')
    bit_stream = list(_bytes_to_bits(length_prefix + payload))
    bit_iter = iter(bit_stream)

    new_pixels = []
    for p in pixels:
        r, g, b = p[:3]
        try:
            r = (r & 0xFE) | next(bit_iter)
        except StopIteration:
            new_pixels.append(p)
            continue
        try:
            g = (g & 0xFE) | next(bit_iter)
        except StopIteration:
            if has_alpha:
                new_pixels.append((r, g, b, p[3]))
            else:
                new_pixels.append((r, g, b))
            continue
        try:
            b = (b & 0xFE) | next(bit_iter)
        except StopIteration:
            if has_alpha:
                new_pixels.append((r, g, b, p[3]))
            else:
                new_pixels.append((r, g, b))
            continue
        if has_alpha:
            new_pixels.append((r, g, b, p[3]))
        else:
            new_pixels.append((r, g, b))

    # Save as PNG
    mode = 'RGBA' if has_alpha else 'RGB'
    out_img = Image.new(mode, (img.width, img.height))
    out_img.putdata(new_pixels)
    # Ensure directory
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    out_img.save(output_path, format='PNG')

def extract_message_from_image(input_path: str) -> bytes:
    with Image.open(input_path) as img:
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        has_alpha = img.mode == 'RGBA'
        pixels = list(img.getdata())

    # Extract bits from R,G, then B
    bits = []
    for p in pixels:
        r, g, b = p[:3]
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    # First 32 bits = length (in bytes)
    length_bytes = _bits_to_bytes(bits[:32])
    length = int.from_bytes(length_bytes, 'big')
    total_bits_needed = 32 + length * 8
    if total_bits_needed > len(bits):
        raise ValueError('Not enough data for payload length')
    payload_bits = bits[32:32 + length * 8]
    payload = _bits_to_bytes(payload_bits)
    return payload
