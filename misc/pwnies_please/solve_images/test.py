import torch
import io
import tempfile
from PIL import Image
import numpy as np


def image_to_tensor(img):
    # convert to numpy array
    tensor = np.array(img).astype(np.float32) / 255.0
    tensor = tensor.transpose(2, 0, 1)
    tensor = tensor[None, :, :, :]  # add batch dimension
    tensor = torch.tensor(tensor, requires_grad=True)
    assert tensor.shape == (1, 3, 32, 32), tensor.shape
    return tensor

def tensor_to_img(tensor):
    tensor = tensor.detach().squeeze().numpy()
    tensor = tensor.transpose(1, 2, 0)
    tensor = (tensor * 255).astype(np.uint8)
    return Image.fromarray(tensor)

def save_image(img, save_file='/tmp/atak.png'):
    if os.path.exists(save_file):
        os.remove(save_file)
    img.save(save_file)

def bytes_to_image(img_data):
    with tempfile.NamedTemporaryFile(suffix='.png') as tmp:
        tmp.write(img_data)
        tmp.flush()
        return Image.open(tmp.name)

img1 = open("black.png", "rb")
img2 = open("white.png", "rb")
# img1 = open("horse-orig.png", "rb")
# img2 = open("horse-line-added.png", "rb")

img1_pil = bytes_to_image(img1.read()) # PIL Image object
img2_pil = bytes_to_image(img2.read())

img1_tensor = image_to_tensor(img1_pil)
img2_tensor = image_to_tensor(img2_pil)

print(img1_tensor)
print(img2_tensor)
# tens_1 = torch.as_tensor(list(img1_pil))
# tens_2 = torch.as_tensor(list(img2_pil))
# print(tens_1)
# print(tens_2)

print(((img1_tensor - img2_tensor)**2).sum())

