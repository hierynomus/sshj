#!/bin/sh
# Don't call it frequently. It's rather a documentation how everything is generated.
ssh-keygen -f resources/users_rsa_ca -t rsa -N ''
mv resources/users_rsa_ca.pub docker-image/test-container
ssh-keygen -f resources/keyfiles/id_rsa2 -t rsa -m pem -N ''
ssh-keygen -s resources/users_rsa_ca -I my_key_id -n sshj resources/keyfiles/id_rsa2.pub