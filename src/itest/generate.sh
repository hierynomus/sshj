#!/usr/bin/env bash
# Don't call it frequently. It's rather a documentation how everything is generated.
set -e -o pipefail
cd "${BASH_SOURCES[0]}"

function generate() {
  local destination="$1"
  if [[ ! -f "$destination" ]]; then
    echo "Generating $destination" 1>&2
    shift
    mkdir -p "$(dirname "$destination")"
    ssh-keygen -q -f "$destination" "${@}"
  fi
}

generate resources/users_rsa_ca -t rsa -N ''
if [[ -f resources/users_rsa_ca.pub ]]; then
  mv resources/users_rsa_ca.pub docker-image/test-container
fi
generate resources/keyfiles/id_rsa2 -t rsa -m pem -N ''
generate resources/keyfiles/id_rsa2-cert.pub -s resources/users_rsa_ca -I my_key_id -n sshj resources/keyfiles/id_rsa2.pub

cat docker-image/test-container/users_rsa_ca.pub >docker-image/test-container/trusted_ca_keys

key_algo_pairs=(ecdsa_256 ecdsa_384 ecdsa_521 rsa_2048 ed25519_384)

for ca_algo in ecdsa rsa ed25519; do
  generate "resources/keyfiles/certificates/CA_${ca_algo}.pem" -N "" -t "$ca_algo" -C "CA_${ca_algo}.pem"
  cat "resources/keyfiles/certificates/CA_${ca_algo}.pem.pub" >>docker-image/test-container/trusted_ca_keys

  for key_algo_pair in "${key_algo_pairs[@]}"; do
    key_algo="${key_algo_pair/_*/}"
    bits="${key_algo_pair/*_/}"

    for format in pem rfc4716; do
      if [[ "$key_algo" == 'pem' && "$format" == 'ed25519' ]]; then
        # Ed25519 keys are always generated in RFC4716 format.
        continue
      fi

      user_key="resources/keyfiles/certificates/id_${key_algo_pair}_${format}_signed_by_${ca_algo}"
      generate "$user_key" -N '' -t "$key_algo" -b "$bits" -m "$format" -C "$(basename "$user_key")"
      generate "${user_key}-cert.pub" -s "resources/keyfiles/certificates/CA_${ca_algo}.pem" -I "$(basename "$user_key")" -n sshj "${user_key}.pub"
    done
  done
done
