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
package com.hierynomus.sshj.transport.mac

import com.hierynomus.sshj.IntegrationBaseSpec
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.transport.mac.HMACRIPEMD160
import net.schmizz.sshj.transport.mac.HMACSHA2256
import spock.lang.Unroll

class MacSpec extends IntegrationBaseSpec {

    @Unroll
    def "should correctly connect with #mac MAC"() {
        given:
        def cfg = new DefaultConfig()
        cfg.setMACFactories(macFactory)
        def client = getConnectedClient(cfg)

        when:
        client.authPublickey(USERNAME, KEYFILE)

        then:
        client.authenticated

        where:
        macFactory << [new HMACSHA2256.Factory(), new HMACRIPEMD160.Factory()]
        mac = macFactory.name
    }
}
