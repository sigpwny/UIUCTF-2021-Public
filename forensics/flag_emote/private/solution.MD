# capture the :flag

## Least Significant Bit

Each pixel consists of 4 channels: Red, Green, Blue, and Alpha as such `(R, G, B, A)`. Each
bit is represented as a number between 0 and 255 inclusive. Thus these are 8-bit numbers.
The intuition for LSB steganography is that the LSB of each number changes the fact that
this bit changes the appearance of that particular pixel the least. Thus it is very hard
to tell that the original image was altered. This challenge only encoded in the `R`, `G`, and
`B` channels

## Decoding flag.png

The title of the challenge `capture the :flag:` was a hint in itself that you should look
at the emote `:flag:` in the server. To get the emote, the easiest way to obtain a full
resolution image is to right click and open link and then download from the browser. After
downloading this image the next piece of information to look at is the image description.
You can use the command link tool `exiftool` to find the image description by typing
`exiftool flag.png` and then seeing in the description the hint `Pixels[1337:]` which means
that you should start reading the message at the 1338th pixel, or with 0 indexing, pixel
number 1337.

To decode the image, create a list of all pixels, `Pixels`, including and after the 1338th
pixel of the image. For this I used the `PIL` library, specifically the `Image` class. Then
from there examine the LSB for the `R`, `G`, and `B` channels. This can be easily done by
looking at the parity of each bit. If the bit is even, the LSB is 0, otherwise it is 1. Then
we can group these LSBs into groups of 8 and from there convert them to base 10 and use ASCII
codes to find the corresponding letter. Since we don't know how long the image is we have to
do this from `Pixels[1337]` to the end.

Then from there we can see the flag is `uiuctf{d!sc0rd_fl4g_h0w_b0ut_d4t}`

I've included solution and source code for encoding your own images. The original image is the
`:white_flag:` emote.
