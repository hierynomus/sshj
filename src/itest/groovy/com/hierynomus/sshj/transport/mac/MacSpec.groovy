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

        cleanup:
        client.disconnect()

        where:
        macFactory << [Macs.HMACRIPEMD160(), Macs.HMACRIPEMD160OpenSsh(), Macs.HMACSHA2256(), Macs.HMACSHA2512()]
        mac = macFactory.name
    }

    @Unroll
    def "should correctly connect with Encrypt-Then-Mac #mac MAC"() {
        given:
        def cfg = new DefaultConfig()
        cfg.setMACFactories(macFactory)
        def client = getConnectedClient(cfg)

        when:
        client.authPublickey(USERNAME, KEYFILE)

        then:
        client.authenticated

        cleanup:
        client.disconnect()

        where:
        macFactory << [Macs.HMACRIPEMD160Etm(), Macs.HMACSHA2256Etm(), Macs.HMACSHA2512Etm()]
        mac = macFactory.name
    }
}
