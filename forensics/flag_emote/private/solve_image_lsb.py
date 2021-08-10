from PIL import Image
import sys

# usage: python3 image_lsb.py [file_to_decode.png]

# get list of all pixels from secret_pixels[1337] and beyond
secret_pixels = []
with Image.open(sys.argv[1]) as secret:
    width, height = secret.size
    for x in range(width):
        for y in range(height):
            pixel = list(secret.getpixel((x, y)))
            secret_pixels.append(pixel)
secret_here = secret_pixels[1337:]

bin_to_decode = ""
for pixel in secret_here:
    for n in range(0, 3):
        # use parity to determine LSB
        if pixel[n] % 2 == 0:
            bin_to_decode += "0"
        else:
            bin_to_decode += "1"

# group in bytes
bin_bytes = [
    bin_to_decode[i * 8 : (i + 1) * 8] for i in range(0, int(len(bin_to_decode) / 8))
]

decoded = ""
for bin_char in bin_bytes:
    # use ASCII to convert from bytes to letter
    c = chr(int(bin_char, base=2))
    decoded += c

# print result
print(decoded)
