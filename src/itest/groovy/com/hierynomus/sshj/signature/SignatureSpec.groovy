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
import com.hierynomus.sshj.key.KeyAlgorithms
import net.schmizz.sshj.DefaultConfig
import spock.lang.Unroll

class SignatureSpec extends IntegrationBaseSpec {

    @Unroll
    def "should correctly connect with #sig Signature"() {
        given:
        def cfg = new DefaultConfig()
        cfg.setKeyAlgorithms(Collections.singletonList(sigFactory))
        def client = getConnectedClient(cfg)

        when:
        client.authPublickey(USERNAME, KEYFILE)

        then:
        client.authenticated

        where:
        sigFactory << [KeyAlgorithms.SSHRSA(), KeyAlgorithms.RSASHA256(), KeyAlgorithms.RSASHA512()]
        sig = sigFactory.name
    }
}
