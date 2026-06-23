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
package net.schmizz.sshj.connection

import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.transport.Transport
import spock.lang.Specification

class ConnectionImplSpec extends Specification {

    private static Transport mockTransport() {
        return Stub(Transport) {
            getConfig() >> new DefaultConfig()
            getTimeoutMs() >> 0
        }
    }

    def "setMaxPacketSize should reject zero"() {
        given:
        def mockTransport = mockTransport()
        def conn = new ConnectionImpl(mockTransport, { c -> null } as net.schmizz.keepalive.KeepAliveProvider)

        when:
        conn.setMaxPacketSize(0)

        then:
        thrown(IllegalArgumentException)
    }

    def "setMaxPacketSize should reject negative value"() {
        given:
        def mockTransport = mockTransport()
        def conn = new ConnectionImpl(mockTransport, { c -> null } as net.schmizz.keepalive.KeepAliveProvider)

        when:
        conn.setMaxPacketSize(-1024)

        then:
        thrown(IllegalArgumentException)
    }

    def "setMaxPacketSize should accept positive value"() {
        given:
        def mockTransport = mockTransport()
        def conn = new ConnectionImpl(mockTransport, { c -> null } as net.schmizz.keepalive.KeepAliveProvider)

        when:
        conn.setMaxPacketSize(65536)

        then:
        conn.getMaxPacketSize() == 65536
    }
}
