FROM python:3.8-alpine

RUN apk update && apk upgrade && apk add socat

RUN mkdir /chal
WORKDIR /chal
COPY . /chal
RUN chmod 555 server.py

RUN adduser -D chalhost
USER chalhost

# This runs a shell command instead of python
# That way you can edit the run.sh script in case you need to make changes to the run environment
# For most challenges, you should not need to though
CMD socat TCP-LISTEN:1337,fork,reuseaddr EXEC:"sh run.sh"