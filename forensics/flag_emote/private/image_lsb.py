from PIL import Image
import sys
import os

# thanks @ian5v for the starter code
# usage: python3 image_lsb.py [file_to_encode.png]
# result: secret.png with flag encoded in LSB starting at pixels[1337]

flag = "uiuctf{d!sc0rd_fl4g_h0w_b0ut_d4t}" # Change this to encode your own message
start_index = 1337 # Change this to configure the starting position
binary_flag = "".join(format(ord(i), "08b") for i in flag)

pixel_number = 0
bin_flag_index = 0

with Image.open(sys.argv[1]) as orig:
    width, height = orig.size
    for x in range(width):
        for y in range(height):
            # modify only the pixels we need
            if pixel_number >= start_index and pixel_number < start_index + int(
                len(binary_flag) / 3
            ):
                pixel = list(orig.getpixel((x, y)))
                for n in range(0, 3):
                    # Clear the lsb and then use bitwise or to encode
                    pixel[n] = pixel[n] & ~1 | int(
                        binary_flag[3 * (pixel_number - start_index) + n]
                    )
                orig.putpixel((x, y), tuple(pixel))
            pixel_number += 1

    orig.save("secret.png", "PNG")

# Change this to encode whatever you want in the description
# This will be executed in command line so use escape characters as needed
description: str = "LSBs\(Pixels[1337:]\)"
os.system("exiftool -description={} secret.png".format(description))
