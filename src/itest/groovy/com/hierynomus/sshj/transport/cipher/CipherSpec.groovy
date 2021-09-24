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
package com.hierynomus.sshj.transport.cipher

import com.hierynomus.sshj.IntegrationBaseSpec
import net.schmizz.sshj.DefaultConfig
import spock.lang.Unroll

class CipherSpec extends IntegrationBaseSpec {

    @Unroll
    def "should correctly connect with #cipher Cipher"() {
        given:
        def cfg = new DefaultConfig()
        cfg.setCipherFactories(cipherFactory)
        def client = getConnectedClient(cfg)

        when:
        client.authPublickey(USERNAME, KEYFILE)

        then:
        client.authenticated

        cleanup:
        client.disconnect()

        where:
        cipherFactory << [BlockCiphers.TripleDESCBC(),
                          BlockCiphers.BlowfishCBC(),
                          BlockCiphers.AES128CBC(),
                          BlockCiphers.AES128CTR(),
                          BlockCiphers.AES192CBC(),
                          BlockCiphers.AES192CTR(),
                          BlockCiphers.AES256CBC(),
                          BlockCiphers.AES256CTR(),
                          GcmCiphers.AES128GCM(),
                          GcmCiphers.AES256GCM(),
                          ChachaPolyCiphers.CHACHA_POLY_OPENSSH()]
        cipher = cipherFactory.name
    }

}
