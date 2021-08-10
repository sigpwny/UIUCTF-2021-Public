#!/usr/bin/env python3
import base64
import os, io
import tempfile

import bs4
import numpy as np
import requests
import torch
import torch.nn as nn
from PIL import Image

from torchvision import models
import torchvision.transforms as transforms
import torchvision 
import torch.nn as nn
import torch

imagenet_class_index = ['plane', 'car', 'bird', 'cat',
                        'deer', 'dog', 'frog', 'horse', 'ship', 'truck']

MODEL_DIR = os.environ.get('MODEL_DIR', '/tmp/pwnies_please/challenge/models/')

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

def image_to_tensor(img):
    # convert to numpy array
    tensor = np.array(img).astype(np.float32) / 255.0
    tensor = tensor.transpose(2, 0, 1)
    tensor = tensor[None, :, :, :]  # add batch dimension
    tensor = torch.tensor(tensor, requires_grad=True)
    assert tensor.shape == (1, 3, 32, 32), tensor.shape
    return tensor

def bytes_to_image(img_data):
    with tempfile.NamedTemporaryFile(suffix='.png') as tmp:
        tmp.write(img_data)
        tmp.flush()
        return Image.open(tmp.name)

# Transform image to normalize into model's bounds
def transform_image(image):
    my_transforms = transforms.Compose([transforms.Resize(256),
                        transforms.CenterCrop(224),
                        transforms.ToTensor(),
                        transforms.Normalize(
                            [0.485, 0.456, 0.406],
                            [0.229, 0.224, 0.225])])
    return my_transforms(image).unsqueeze(0)

def get_image_to_attack(url='http://54.184.185.227:5000'):
    response = requests.get(url)
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

def main():

    #inputs = transform_image(image_bytes=image_bytes)

    img = get_image_to_attack('http://54.184.185.227:5000')
    model1 = get_model("pwny_cifar_eps_0.pth")   # nonrobust
    model2 = get_model("pwny_cifar_eps_0.5.pth") # robust
    #tensor = image_to_tensor(img)
    tensor = transform_image(img)
    tensor = torch.tensor(tensor, requires_grad=True)
    output1 = model1(tensor)
    output2 = model2(tensor)
    preds1 = torch.argmax(output1, 1)
    preds2 = torch.argmax(output2, 1)
    # print(preds)
    classify_result1 = imagenet_class_index[preds1]
    print("nonrobust:\t",classify_result1, end="\t")
    classify_result2 = imagenet_class_index[preds2]
    print("robust:\t",classify_result2)

print("fetching an image from the server and classifying it using both models")
for x in range(10):
    main()
