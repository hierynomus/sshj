package com.hierynomus.sshj.signature

import com.hierynomus.sshj.IntegrationBaseSpec
import spock.lang.Unroll

class KeyWithCertificateSpec extends IntegrationBaseSpec {

    @Unroll
    def "authorising with a signed public key #keyName"() {
        given:
        def client = getConnectedClient()

        when:
        client.authPublickey(USERNAME, "src/itest/resources/keyfiles/certificates/$keyName")

        then:
        client.authenticated

        where:
        keyName << [
                "id_ecdsa_256_pem_signed_by_ecdsa",
                "id_ecdsa_256_rfc4716_signed_by_ecdsa",
                "id_ecdsa_256_pem_signed_by_ed25519",
                "id_ecdsa_256_rfc4716_signed_by_ed25519",
                "id_ecdsa_256_pem_signed_by_rsa",
                "id_ecdsa_256_rfc4716_signed_by_rsa",
                "id_ecdsa_384_pem_signed_by_ecdsa",
                "id_ecdsa_384_rfc4716_signed_by_ecdsa",
                "id_ecdsa_384_pem_signed_by_ed25519",
                "id_ecdsa_384_rfc4716_signed_by_ed25519",
                "id_ecdsa_384_pem_signed_by_rsa",
                "id_ecdsa_384_rfc4716_signed_by_rsa",
                "id_ecdsa_521_pem_signed_by_ecdsa",
                "id_ecdsa_521_rfc4716_signed_by_ecdsa",
                "id_ecdsa_521_pem_signed_by_ed25519",
                "id_ecdsa_521_rfc4716_signed_by_ed25519",
                "id_ecdsa_521_pem_signed_by_rsa",
                "id_ecdsa_521_rfc4716_signed_by_rsa",
                "id_rsa_2048_pem_signed_by_ecdsa",
                "id_rsa_2048_rfc4716_signed_by_ecdsa",
                "id_rsa_2048_pem_signed_by_ed25519",
                "id_rsa_2048_rfc4716_signed_by_ed25519",
                "id_rsa_2048_pem_signed_by_rsa",
                "id_rsa_2048_rfc4716_signed_by_rsa",
                "id_ed25519_384_rfc4716_signed_by_ecdsa",
                "id_ed25519_384_rfc4716_signed_by_ed25519",
                "id_ed25519_384_rfc4716_signed_by_rsa",
        ]
    }
}
