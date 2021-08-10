FROM python:3

RUN apt-get update
RUN apt-get install -y socat
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/chal
WORKDIR /opt/chal
RUN cd /opt/chal

COPY pow_erful.py .

RUN adduser chal
USER chal
ENV FLAG="uiuctf{bitcoin_to_the_moon}"
CMD socat -vvv -T60 tcp-listen:1337,fork,reuseaddr system:"python3 pow_erful.py 2>&1"
