FROM python:3

RUN apt-get update
RUN apt-get install -y socat
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/chal
WORKDIR /opt/chal

COPY requirements.txt ./
RUN python3 -m pip install -r requirements.txt

COPY flag.txt dhke_adventure.py ./

RUN adduser chal
USER chal
ENV FLAG="uiuctf{give_me_chocolate_every_day_7b8b06}"
CMD socat -vvv -T60 tcp-listen:1337,fork,reuseaddr system:"python3 dhke_adventure.py 2>&1"
