#!/usr/bin/env python3

# %%
import base64
import os, io
import tempfile
import itertools
import random

import bs4
import numpy as np
import requests
import torch
import torch.nn as nn
from PIL import Image
from PIL import ImageDraw

from torchvision import models
import torchvision.transforms as transforms
import torchvision 
import torch.nn as nn
import torch


TARGET_CLASS_NAME = 'frog'
MODEL_DIR = os.environ.get('MODEL_DIR', '/tmp/pwnies_please/challenge/models/')
imagenet_class_index = ['plane', 'car', 'bird', 'cat',
                        'deer', 'dog', 'frog', 'horse', 'ship', 'truck']
session = requests.Session()

# load model
device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
model_nonrobust = models.resnet18()
num_ftrs = model_nonrobust.fc.in_features
model_nonrobust.fc = nn.Linear(num_ftrs, len(imagenet_class_index))
model_nonrobust.load_state_dict(torch.load("./challenge/models/pwny_cifar_eps_0.pth", map_location = device))
model_ft = model_nonrobust.to(device)
model_nonrobust.eval()

def get_model(model_name="pwny_cifar_eps_0.pth"):
    # Loads the model onto the cpu
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model = models.resnet18()
    num_ftrs = model.fc.in_features
    model.fc = nn.Linear(num_ftrs, len(imagenet_class_index))
    model.load_state_dict(torch.load(os.path.join(
        MODEL_DIR, model_name), map_location=device))
    model.eval()
    return model


def bytes_to_image(img_data):
    with tempfile.NamedTemporaryFile(suffix='.png') as tmp:
        tmp.write(img_data)
        tmp.flush()
        return Image.open(tmp.name)


def get_image_to_attack(url='http://54.184.185.227:5000'):
    '''
    uses session global
    '''
    response = session.get(url)
    # req.raise_for_status() # check was successful
    text = response.text
    soup = bs4.BeautifulSoup(text, 'html.parser')
    img_tag = soup.find('img')
    img_string = img_tag['src']
    img_string[:100]
    FOUND = 'data:image/png;base64,'
    assert img_string.startswith(FOUND), img_string[:100]

    img_data = base64.b64decode(img_string[len(FOUND):])
    return bytes_to_image(img_data)


def image_to_tensor(img):
    # convert to numpy array
    tensor = np.array(img).astype(np.float32) / 255.0
    tensor = tensor.transpose(2, 0, 1)
    tensor = tensor[None, :, :, :]  # add batch dimension
    tensor = torch.tensor(tensor, requires_grad=True)
    assert tensor.shape == (1, 3, 224, 224), tensor.shape
    return tensor


def image_diff(A, B):
    return ((A - B) ** 2).sum()


def fake_normalize(t):
    mean = torch.tensor([0.485, 0.456, 0.406]).reshape(-1, 1, 1)
    stdev = torch.tensor([0.229, 0.224, 0.225]).reshape(-1, 1, 1)
    return (t - mean) / stdev

def fake_denormalize(t):
    mean = torch.tensor([0.485, 0.456, 0.406]).reshape(-1, 1, 1)
    stdev = torch.tensor([0.229, 0.224, 0.225]).reshape(-1, 1, 1)
    return t * stdev + mean

def attack_image(atak_image):
    atak_image = atak_image.copy()
    draw = ImageDraw.ImageDraw(atak_image)
    vertices = []
    for i in range(8):
        vertices.append((random.randint(0, 224), random.randint(0, 224)))
    draw.line(vertices, width=2, fill=(255, 0, 0))
    return atak_image

class UnNormalize(object):
    def __init__(self, mean, std):
        self.mean = mean
        self.std = std

    def __call__(self, tensor):
        """
        Args:
            tensor (Tensor): Tensor image of size (C, H, W) to be normalized.
        Returns:
            Tensor: Normalized image.
        """
        for t, m, s in zip(tensor, self.mean, self.std):
            t.mul_(s).add_(m)
            # The normalize code -> t.sub_(m).div_(s)
        return tensor

# unorm = UnNormalize(mean=(0.485, 0.456, 0.406), std=(0.229, 0.224, 0.225))
# unorm(tensor)

def tensor_to_img(tensor):
    # TODO: undo Normalize operation
    # torch.lingalg.inv()
    # my_transforms = transforms.Compose([
    #                     transforms.ToTensor(),
    #                     transforms.Normalize(
    #                         [0.485, 0.456, 0.406],
    #                         [0.229, 0.224, 0.225])])
    # image = Image.open(io.BytesIO(image_bytes))
    # return my_transforms(image).unsqueeze(0)

    tensor = tensor.detach().squeeze().numpy()
    tensor = tensor.transpose(1, 2, 0)
    tensor = (tensor * 255).astype(np.uint8)
    return Image.fromarray(tensor)


def save_image(img, save_file='/tmp/atak.png'):
    if os.path.exists(save_file):
        os.remove(save_file)
    img.save(save_file)

# Transform image to normalize into model's bounds
def transform_image(image_bytes):
    my_transforms = transforms.Compose([#transforms.Resize(256),
                        #transforms.CenterCrop(224),
                        transforms.ToTensor(),
                        transforms.Normalize(
                            [0.485, 0.456, 0.406],
                            [0.229, 0.224, 0.225])])
    image = Image.open(io.BytesIO(image_bytes))
    return my_transforms(image).unsqueeze(0)

# Use imagehash to compare relative closeness of image (can't just allow random images to be thrown at the model...)
def get_prediction(image_bytes, model):
    inputs = transform_image(image_bytes=image_bytes)
    outputs = model(inputs)
    preds = torch.argmax(outputs, 1)
    input_image = Image.open(io.BytesIO(image_bytes))

    return imagenet_class_index[preds]

def post_adversarial_image(url='http://54.184.185.227:5000', img_file='/tmp/atak.png'):
    '''
    POSTs image to server
    '''

    files = {'file': open(img_file, 'rb')}
    response = session.post(url, files=files)

    soup = bs4.BeautifulSoup(response.text, 'html.parser')
    div = soup.find('div', {"id": "response"})
    return div.text # the line of the response we care about, contains # of pwnies

def main():
    model = get_model()
    atak_image = get_image_to_attack()
    atak_image = attack_image(atak_image)
    save_image(atak_image)
    # result = post_adversarial_image(url="http://localhost:5001")

    # now, run the adversarial image against the clientside copy of the nonrobust model
    # img_byte_arr = io.BytesIO()
    # img.save(img_byte_arr, format='PNG')
    # img_byte_arr = img_byte_arr.getvalue()

    # nonrobust = get_prediction(image_bytes = img_byte_arr, model = model_nonrobust)

    result = post_adversarial_image()
    return result

for x in range(100):
    r = main()
    print(r)


