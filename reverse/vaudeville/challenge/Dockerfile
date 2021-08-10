FROM gcr.io/kctf-docker/challenge@sha256:460914265211af5fd006c4ceb4d2628817e9645570033827cf8db136a540b54f

COPY flag.txt /
COPY vaudeville /home/user/

CMD kctf_setup && \
    mount -t tmpfs none /tmp && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow /home/user/vaudeville"
