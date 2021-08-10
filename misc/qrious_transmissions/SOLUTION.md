```python

from PIL import Image


image_height = image_width = 200


cmap = {'0': 0,
        '1': 1}

with open ("info.txt", "r") as gates_file:
    file_data=gates_file.read()

gates = file_data.split(' ')

state = [False, False]
finbin = ""

for x in gates:
    if x == "X":
        state[1] = not state[1]
    elif x == "Z":
        state[0] = not state[0]
    elif x == "ZX":
        state[1] = not state[1]
        state[0] = not state[0]

    finbin += str(int(state[0]))
    finbin += str(int(state[1]))


with open ("output", "w") as outfile:
    outfile_data = outfile.write(finbin)
    outfile.close()

with open ("output", "r") as outfile:
    outfile = filex.read()

im = Image.new('1', (200,200), "black")

data = [cmap[letter] for letter in outfile]
im.putdata(data)
im.show()
```

The image will be a QR Code, scan it to get the flag.