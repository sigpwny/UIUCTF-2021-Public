import io
import os
import random
import base64
import json
from flask import Flask, jsonify, request, render_template, session
from flask_kvsession import KVSessionExtension
import numpy as np

from sqlalchemy import create_engine, MetaData
from simplekv.db.sql import SQLAlchemyStore
from datetime import timedelta

from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from PIL import Image
import imagehash

from torchvision import models
import torchvision.transforms as transforms
import torchvision 
import torch.nn as nn
import torch

# Use environment variable if it exists
FLAG = os.environ.get("FLAG", "uiuctf{fake_flag}")
MIN_LEVEL = 50
SESSION_MINUTES = 5
MUST_REPEAT_CAPTCHA = True
HASH_DIFFERENCE = 5 # how different the imagehash is

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(64)

# Store local session
engine = create_engine('sqlite:////tmp/sessions.db')
metadata = MetaData(bind=engine)
store = SQLAlchemyStore(engine, metadata, 'kvsession_table')
metadata.create_all()
kvsession_extension = KVSessionExtension(store, app)

app.permanent_session_lifetime = timedelta(minutes=SESSION_MINUTES)


# ------------------ Model goes here ⬇------------------ #
imagenet_class_index = ['plane', 'car', 'bird', 'cat', 'deer', 'dog', 'frog', 'horse', 'ship', 'truck']
device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

model_nonrobust = models.resnet18()
num_ftrs = model_nonrobust.fc.in_features
model_nonrobust.fc = nn.Linear(num_ftrs, len(imagenet_class_index))
model_nonrobust.load_state_dict(torch.load("./models/pwny_cifar_eps_0.pth", map_location = device))
model_ft = model_nonrobust.to(device)
model_nonrobust.eval()

model_robust = models.resnet18()
num_ftrs = model_robust.fc.in_features
model_robust.fc = nn.Linear(num_ftrs, len(imagenet_class_index))
model_robust.load_state_dict(torch.load("./models/pwny_cifar_eps_0.5.pth", map_location = device))
model_ft = model_robust.to(device)
model_robust.eval()

image_set = torchvision.datasets.CIFAR10(root='static/images', train=False, download=True)
# ------------------ Model goes here ------------------ #

# Get a random image and show it to the user
def gen_img():
    label = 0
    while label != 7:
        curr_image, label = image_set[random.randint(1, len(image_set))] # we found the off-by-one but decided to leave it in for extra flavor 🌶

    resize_images = transforms.Compose([transforms.Resize(256),
                        transforms.CenterCrop(224)])
    curr_image = resize_images(curr_image)

    buffered = io.BytesIO()
    curr_image.save(buffered, format='png')
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

# Transform image to normalize into model's bounds
def transform_image(image_bytes):
    my_transforms = transforms.Compose([
                        transforms.ToTensor(),
                        transforms.Normalize(
                            [0.485, 0.456, 0.406],
                            [0.229, 0.224, 0.225])])
    image = Image.open(io.BytesIO(image_bytes))
    return my_transforms(image).unsqueeze(0)


def tensor_to_image(tensor):
    tensor = tensor.detach().squeeze().numpy()
    tensor = tensor.transpose(1, 2, 0)
    tensor = (tensor * 255).astype(np.uint8)
    return Image.fromarray(tensor)

def image_to_tensor(img):
    tensor = np.array(img).astype(np.float32) / 255.0
    # HWC -> CHW
    tensor = tensor.transpose(2, 0, 1)
    tensor = tensor[None, :, :, :]  # add batch dimension
    return torch.tensor(tensor, requires_grad=True)

def bytes_to_image(img_data):
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.png') as tmp:
        tmp.write(img_data)
        tmp.flush()
        return Image.open(tmp.name)

def unused_get_prediction(image_bytes, model, curr_image = None):
    input_img = bytes_to_image(image_bytes)
    input_img_tensor = image_to_tensor(input_img)

    original_img = Image.open(io.BytesIO(base64.b64decode(curr_image)))
    orig_img_tensor = image_to_tensor(original_img)

    outputs = model(input_img_tensor)
    preds = torch.argmax(outputs, 1)

    # how much they are allowed to change the image
    # threshold: float from 0 to 1?
    # TODO: TUNE ME
    # range of possible values is 0 - 3072 (3072 = 32 * 32 * 3)
    # we probably want 5-15% different. x / 3072
    if ((orig_img_tensor - input_img_tensor)**2).sum() < 500:
        return imagenet_class_index[preds]
    else:
        return "IMAGE WAS TOO DIFFERENT"

# Use imagehash to compare relative closeness of image (can't just allow random images to be thrown at the model...)
def get_prediction(image_bytes, model, curr_image = None):
    inputs = transform_image(image_bytes=image_bytes)
    outputs = model(inputs)
    preds = torch.argmax(outputs, 1)
    original = Image.open(io.BytesIO(base64.b64decode(curr_image)))

    # "where the magic happens" - akshunna
    input_image = Image.open(io.BytesIO(image_bytes))
    hash_orig = imagehash.average_hash(original)
    hash_input = imagehash.average_hash(input_image)

        # currently HASH_DIFFERENCE is 5
        # is number of bits changed in the hash
        # hash is 64 bits long
        # up to 5 hex digits can be different
        # 16 hex digits
        # 256b hash
        # 0xffff ffff ffff ffff ffff ffff ffff ffff
    if hash_orig - hash_input < HASH_DIFFERENCE:
        return imagenet_class_index[preds]
    else:
        return "IMAGE WAS TOO DIFFERENT"

# Function that takes care of the website's repeated image generation and edge conditions
@app.route('/', methods=['GET', 'POST'])
def index():

    response = None
    img = None
        # regen_image is a bool checking if session.get('img') is None
    regen_image = session.get('img') is None

    if session.get('level') is None:
        session['level'] = 0
        session['yolo'] = 0
        session.permanent = True
    
    if request.method == 'POST' and 'img' in session:
        file = request.files['file']
        img_bytes = file.read()
        
        image = bytes_to_image(img_bytes)
        (width, height) = image.size 
        depth = len(image.getbands())

        if width != 224 or height != 224 or depth != 3:
            response = f"Invalid image shape. Expecting 224 x 224 with 3 channels, got {width} x {height} with {depth} channels"
        else:   
            nonrobust = get_prediction(image_bytes=img_bytes, model = model_nonrobust, curr_image = session['img'])
            robust = get_prediction(image_bytes=img_bytes, model = model_robust, curr_image = session['img'])
            # robust model is the "ground truth", non-robust is the "bouncer"
            # cases:
                # bouncer does not want to let in horses, you want to let them in anyway
                # robust says horse, non-robust says horse: you have been detected
                # robust says not horse, non-robust says horse: you fail extra hard
                # robust says horse, non-robust says not horse: flag
                # robust says not horse, non-robust says not horse: they were let in but you didn't achieve the goal
            regen_image = True
            if robust != 'horse':
                response = "you snuck SOMETHING into the club but it wasn't a pwny (changed too much, ground truth thinks image is a: robust {}\tnonrobust {})".format(robust, nonrobust)
                session['yolo'] += 1
            elif robust == 'horse' and nonrobust != 'horse':
                session['level'] = session['level'] + 1
                session['yolo'] = 0
                response = "success! the bouncer thought your horse was a: {}".format(nonrobust)
                # response = "robust = {}, nonrobust = {}".format(robust, nonrobust)
            else: # robust == 'horse' and nonrobust == 'horse': 
                response = "bouncer saw through your disguise. bouncer: rules say \"NO HORSEPLAY\""
                session['yolo'] += 1
                # response += "\nrobust {}\tnonrobust {}".format(robust, nonrobust)
                # this is the most common fail condition
            if session['yolo'] > 3:
                session['yolo'] = 0
                session['level'] = 0
                response = "bouncer smacks you and you pass out, start over :)"

    if session['level'] >= MIN_LEVEL:
        response = FLAG
    elif response is None:
        response = "Hmm, alright, you've gotten %d horses into the club." % session['level']

    if regen_image or not MUST_REPEAT_CAPTCHA:
        img = gen_img()
        session['img'] = img
    else:
        img = session['img']

    return render_template('index.html', response = response, b64png = img)

@app.errorhandler(RuntimeError)
def error_handler(e):
    # TODO: How do you want to censor these?
    return render_template('error.html', error = str(e))

if __name__ == '__main__': # python app.py
    app.run(host='0.0.0.0')
