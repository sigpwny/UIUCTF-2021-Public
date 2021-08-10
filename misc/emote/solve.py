from PIL import Image
im = Image.open('867546536417951754.png')

pixels = list(im.getdata())
width, height = im.size

# print(pixels, width, height)


# pixels [0, 255, 255, 255, 0, 255, 0, 255, 0, 255, 255, 0, 255,
def l(x):
    if x == 0:
        return 0
    else:
        return 1
bitarray = list(map(l, pixels))
# print(bitarray)

h = []
for x in range(0, len(pixels), 8):
    a = [str(o) for o in bitarray[x:x+8]]
    a = ''.join(a)
    value = int(a, 2)
    h.append(chr(value))

h = ''.join(h)
assert h == "uiuctf{staring_at_pixels_is_fun}"
print("correct!")
