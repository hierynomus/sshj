/*
 * Copyright (C)2009 - SSHJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
