FROM ubuntu:20.04

# Install OpenSSH server
RUN apt-get update && apt-get install openssh-server -y

# Add user "red"
RUN useradd -m red -s /bin/bash
RUN usermod -p '*' red

# Setup challenge related files
RUN mkdir /srv/...
COPY important_data.jpg /srv/.../important_data.jpg
RUN chmod -R 555 /srv/...
COPY .bash_history /home/red/.bash_history

# Enable SSH pubkey authentication on port 42069
COPY id_rsa.pub /home/red/.ssh/authorized_keys
COPY sshd_config /etc/ssh/sshd_config
RUN chown -R red:red /home/red && chmod -R 555 /home/red
EXPOSE 42069
RUN service ssh restart

CMD ["/usr/sbin/sshd","-D"]
