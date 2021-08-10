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

# %%
TARGET_CLASS_NAME = 'frog'

# %%
model_dir = '/home/ubuntu/pwnies_please/challenge/models/'
imagenet_class_index = ('plane', 'car', 'bird', 'cat', 'deer', 'dog', 'frog', 'horse', 'ship', 'truck')
model = models.resnet18()
num_ftrs = model.fc.in_features
model.fc = nn.Linear(num_ftrs, len(imagenet_class_index))
model.load_state_dict(torch.load(os.path.join(model_dir, "pwny_cifar_eps_0.pth"), map_location = device))
model.eval()

#%%
url = 'http://54.184.185.227:5000'
r = requests.get(url)
import pdb ; pdb.set_trace()
r.raise_for_status()
text = r.text
soup = bs4.BeautifulSoup(text, 'html.parser')
img_tag = soup.find('img')
img_string = img_tag['src']
img_string[:100]
FOUND = 'data:image/png;base64,'
assert img_string.startswith(FOUND), img_string[:100]

img_data = base64.b64decode(img_string[len(FOUND):])
with tempfile.NamedTemporaryFile(suffix='.png') as tmp:
    tmp.write(img_data)
    tmp.flush()
    img = Image.open(tmp.name)

# convert to numpy array
atak_img = np.array(img).astype(np.float32) / 255.0
atak_img = atak_img.transpose(2, 0, 1)
atak_img = atak_img[None, :, :, :]  # add batch dimension

# convert to tensor
atak_image = torch.tensor(atak_img, requires_grad=True)

# %%
# Class we want to "turn the horse into" -- currently 'frog'
target = torch.tensor([imagenet_class_index.index(TARGET_CLASS_NAME)])
optimizer = torch.optim.Adam([atak_image], lr=0.001)
criterion = nn.CrossEntropyLoss()

for i in range(1000):
    optimizer.zero_grad()
    output = model(atak_image)
    loss = criterion(output, target)
    if i % 100 == 0:
        print(i, 'loss', loss)
    loss.backward()
    optimizer.step()  # this updates the image to be slightly more 'frog'

# %% # Save image as png
atak_result = atak_image.detach().squeeze().numpy()
atak_result = atak_result.transpose(1, 2, 0)
atak_result = (atak_result * 255).astype(np.uint8)
atak_result = Image.fromarray(atak_result)
atak_result.save('/tmp/atak.png')


