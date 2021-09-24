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
import net.schmizz.sshj.DefaultConfig
import spock.lang.Unroll

class RsaSignatureClientKeySpec extends IntegrationBaseSpec {
    @Unroll
    def "should correctly connect using publickey auth with RSA key with signature"() {
        given:
        def client = getConnectedClient(new DefaultConfig())

        when:
        client.authPublickey(USERNAME, "src/itest/resources/keyfiles/id_rsa2")

        then:
        client.authenticated
    }
}
