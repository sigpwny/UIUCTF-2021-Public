# turns strings into pngs
from PIL import Image

flag = "uiuctf{staring_at_pixels_is_fun}"
assert len(flag) == 32
assert len(flag) * 8 == 256
assert 32 * 8 == 256
assert 16 * 16 == 256

b = flag.encode('utf-8')

mode = "1" # 1 bit pixels, 1 pixel per byte
# mode = "L" # 8 bit b/w pixels
# see docs for more
# https://pillow.readthedocs.io/en/stable/handbook/concepts.html#concept-modes
s = 16
size = (s,s)
# size = (256,1)
Image.frombytes(mode, size, b).save("foo.png")
