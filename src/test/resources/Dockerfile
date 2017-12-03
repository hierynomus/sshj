FROM sickp/alpine-sshd:7.5
ADD https://raw.githubusercontent.com/Igerly/sshj/master/src/test/resources/id_rsa.pub /home/sickp/.ssh/authorized_keys
RUN \
  echo "root:sunshine" | chpasswd && \
  adduser -D -s /bin/ash sickp && \
  passwd -u sickp && \
  chown -R sickp:sickp /home/sickp
  
