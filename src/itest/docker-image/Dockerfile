FROM sickp/alpine-sshd:7.5-r2

ADD authorized_keys /home/sshj/.ssh/authorized_keys

ADD test-container/ssh_host_ecdsa_key     /etc/ssh/ssh_host_ecdsa_key
ADD test-container/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_ecdsa_key.pub
ADD test-container/ssh_host_ed25519_key   /etc/ssh/ssh_host_ed25519_key
ADD test-container/ssh_host_ed25519_key.pub   /etc/ssh/ssh_host_ed25519_key.pub
ADD test-container/sshd_config /etc/ssh/sshd_config
COPY test-container/trusted_ca_keys /etc/ssh/trusted_ca_keys
COPY test-container/host_keys/* /etc/ssh/

RUN apk add --no-cache tini
RUN \
  echo "root:smile" | chpasswd && \
  adduser -D -s /bin/ash sshj && \
  passwd -u sshj && \
  echo "sshj:ultrapassword" | chpasswd && \
  chmod 600 /home/sshj/.ssh/authorized_keys && \
  chmod 600 /etc/ssh/ssh_host_*_key && \
  chmod 644 /etc/ssh/*.pub && \
  chown -R sshj:sshj /home/sshj

ENTRYPOINT ["/sbin/tini", "/entrypoint.sh", "-o", "LogLevel=DEBUG2"]