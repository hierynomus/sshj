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
package net.schmizz.sshj

import com.hierynomus.sshj.key.KeyAlgorithms
import spock.lang.Specification

class ConfigImplSpec extends Specification {
    static def ECDSA = KeyAlgorithms.ECDSASHANistp521()
    static def ED25519 = KeyAlgorithms.EdDSA25519()
    static def RSA_SHA_256 = KeyAlgorithms.RSASHA256()
    static def RSA_SHA_512 = KeyAlgorithms.RSASHA512()
    static def SSH_RSA = KeyAlgorithms.SSHRSA()

    def "prioritizeSshRsaKeyAlgorithm does nothing if there is no ssh-rsa"() {
        given:
        def config = new DefaultConfig()
        config.keyAlgorithms = [RSA_SHA_512, ED25519]

        when:
        config.prioritizeSshRsaKeyAlgorithm()

        then:
        config.keyAlgorithms == [RSA_SHA_512, ED25519]
    }

    def "prioritizeSshRsaKeyAlgorithm does nothing if there is no rsa-sha2-any"() {
        given:
        def config = new DefaultConfig()
        config.keyAlgorithms = [ED25519, SSH_RSA, ECDSA]

        when:
        config.prioritizeSshRsaKeyAlgorithm()

        then:
        config.keyAlgorithms == [ED25519, SSH_RSA, ECDSA]
    }

    def "prioritizeSshRsaKeyAlgorithm does nothing if ssh-rsa already has higher priority"() {
        given:
        def config = new DefaultConfig()
        config.keyAlgorithms = [ED25519, SSH_RSA, RSA_SHA_512, ECDSA]

        when:
        config.prioritizeSshRsaKeyAlgorithm()

        then:
        config.keyAlgorithms == [ED25519, SSH_RSA, RSA_SHA_512, ECDSA]
    }

    def "prioritizeSshRsaKeyAlgorithm prioritizes ssh-rsa if there is one rsa-sha2-any is prioritized"() {
        given:
        def config = new DefaultConfig()
        config.keyAlgorithms = [ED25519, RSA_SHA_512, ECDSA, SSH_RSA]

        when:
        config.prioritizeSshRsaKeyAlgorithm()

        then:
        config.keyAlgorithms == [ED25519, SSH_RSA, RSA_SHA_512, ECDSA]
    }

    def "prioritizeSshRsaKeyAlgorithm prioritizes ssh-rsa if there are two rsa-sha2-any is prioritized"() {
        given:
        def config = new DefaultConfig()
        config.keyAlgorithms = [ED25519, RSA_SHA_512, ECDSA, RSA_SHA_256, SSH_RSA]

        when:
        config.prioritizeSshRsaKeyAlgorithm()

        then:
        config.keyAlgorithms == [ED25519, SSH_RSA, RSA_SHA_512, ECDSA, RSA_SHA_256]
    }
}
