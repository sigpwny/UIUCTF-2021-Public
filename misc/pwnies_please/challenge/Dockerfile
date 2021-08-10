FROM python:3

RUN mkdir /usr/src/app
WORKDIR /usr/src/app

# create user
RUN groupadd chalusr
RUN useradd -ms /bin/bash -g chalusr chalusr

# pip & apt
COPY ./site/requirements.txt ./
RUN apt update && apt upgrade -y
RUN apt install python3 python3-pip python3-flask -y
RUN pip3 install --no-cache-dir -r requirements.txt

COPY ./site .
COPY ./models ./models
COPY ./models/pwny_cifar_eps_0.pth ./static
COPY ./web.py ./static

RUN mkdir /usr/src/app/static/images
ENV FLAG=uiuctf{th4nks_f0r_th3_pwni3s}
#RUN chown -R chalusr:chalusr /usr/src/app

#USER chalusr

#CMD [ "python3", "./app.py" ]
CMD mount -t tmpfs none /tmp && mount -t tmpfs none /usr/src/app/static/images && python3 ./app.py
#CMD mount -t tmpfs none /tmp && /bin/bash

