#!/usr/bin/env bash
# This script is intended for generating SSH keys required for unit and integration tests. If you intend to add a new
# key to the tests, please write its generation command there.
#
# All generation commands should generate only files that does not exist. If some key is already generated, the script
# should not overwrite the key.

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

function generate_cert() {
  local private_key
  local suffix
  local cert
  private_key="$1"
  suffix="$2"
  shift 2
  cert="$private_key$suffix-cert.pub"
  if [[ ! -f "$cert" ]]; then
    cp "$private_key" "$private_key$suffix"
    cp "$private_key.pub" "$private_key$suffix.pub"
    generate "$cert" "$@" "$private_key$suffix.pub"
    rm -f "$private_key$suffix" "$private_key$suffix.pub"
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

      # These certificates are to be used as host certificates of sshd.
      generate_cert "$user_key" _host \
        -s "resources/keyfiles/certificates/CA_${ca_algo}.pem" -I "$(basename "$user_key")" -h -n 127.0.0.1
    done
  done
done

mkdir -p docker-image/test-container/host_keys

for key_algo_pair in "${key_algo_pairs[@]}"; do
  key_algo="${key_algo_pair/_*/}"
  bits="${key_algo_pair/*_/}"

  user_key="resources/keyfiles/certificates/id_${key_algo_pair}_${format}_signed_by_rsa"
  host_key="docker-image/test-container/host_keys/ssh_host_${key_algo_pair}_key"
  if [[ ! -f "$host_key" ]]; then
    cp -p "$user_key" "$host_key"
    cp -p "${user_key}.pub" "${host_key}.pub"
    cp -p "${user_key}_host-cert.pub" "${host_key}-cert.pub"
  fi
done

(
  cd resources/keyfiles/certificates

  generate_cert id_ed25519_384_rfc4716_signed_by_rsa _host_valid_before_past \
    -s "CA_rsa.pem" -I valid_before_past -h -n 127.0.0.1 -V 'always:20210101000000'

  generate_cert id_ed25519_384_rfc4716_signed_by_rsa _host_valid_after_future \
    -s "CA_rsa.pem" -I valid_after_future -h -n 127.0.0.1 -V '20990101000000:forever'

  generate_cert id_ed25519_384_rfc4716_signed_by_rsa _host_no_principal \
    -s "CA_rsa.pem" -I no_principal -h

  generate_cert id_ed25519_384_rfc4716_signed_by_rsa _host_principal_wildcard_example_com \
    -s "CA_rsa.pem" -I principal_wildcard_example_com -h -n '*.example.com'
)
