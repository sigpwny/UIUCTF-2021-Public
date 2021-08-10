#!/usr/bin/env python3

# %%
import base64
import os
import tempfile

import bs4
import numpy as np
import requests
import torch
import torch.nn as nn
from PIL import Image
from torchvision import models


TARGET_CLASS_NAME = 'frog'
MODEL_DIR = os.environ.get('MODEL_DIR', '/tmp/pwnies_please/challenge/models/')
MAX_SQUARED_DIFFERENCE = 1.0  # TODO: this needs tuning
imagenet_class_index = ('plane', 'car', 'bird', 'cat',
                        'deer', 'dog', 'frog', 'horse', 'ship', 'truck')
sess = requests.Session()

# TODO: 
# WRITE PYTHON REQUESTS TO SUBMIT MULTIPLE ADVERSARIAL IMAGES
# 
# make a session
# get image sess.get('the_url')
# adversarial-ify the image
# sess.post(adversarial_image)
# print last response to see that the number has incremented

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
    req = requests.get(url)
    req.raise_for_status()
    text = req.text
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
    assert tensor.shape == (1, 3, 32, 32), tensor.shape
    return tensor


def image_diff(A, B):
    return ((A - B) ** 2).sum()


def attack_image_tensor(atak_image, model):
    orig_image = atak_image.detach().clone()
    target = torch.tensor([imagenet_class_index.index(TARGET_CLASS_NAME)])
    optimizer = torch.optim.Adam([atak_image], lr=0.001)
    criterion = nn.CrossEntropyLoss()

    for i in range(100):
        optimizer.zero_grad()
        output = model(atak_image)
        loss = criterion(output, target)
        if i % 10 == 0:
            diff = image_diff(atak_image, orig_image)
            print(i, 'loss', loss.item(), 'diff', diff.item())
        loss.backward()
        optimizer.step()

    return atak_image


def tensor_to_img(tensor):
    tensor = tensor.detach().squeeze().numpy()
    tensor = tensor.transpose(1, 2, 0)
    tensor = (tensor * 255).astype(np.uint8)
    return Image.fromarray(tensor)


def save_image(img, save_file='/tmp/atak.png'):
    if os.path.exists(save_file):
        os.remove(save_file)
    img.save(save_file)


# %%
model = get_model()
atak_tensor = image_to_tensor(get_image_to_attack())
atak_tensor = attack_image_tensor(atak_tensor, model)
save_image(tensor_to_img(atak_tensor))

