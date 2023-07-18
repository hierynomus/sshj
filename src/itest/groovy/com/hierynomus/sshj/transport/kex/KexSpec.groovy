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
package com.hierynomus.sshj.transport.kex

import com.hierynomus.sshj.IntegrationTestUtil
import com.hierynomus.sshj.SshdContainer
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.transport.kex.Curve25519SHA256
import net.schmizz.sshj.transport.kex.DHGexSHA1
import net.schmizz.sshj.transport.kex.DHGexSHA256
import net.schmizz.sshj.transport.kex.ECDHNistP
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import spock.lang.Specification
import spock.lang.Unroll

@Testcontainers
class KexSpec extends Specification {
    @Container
    static SshdContainer sshd = new SshdContainer()

    @Unroll
    def "should correctly connect with #kex Key Exchange"() {
        given:
        def cfg = new DefaultConfig()
        cfg.setKeyExchangeFactories(kexFactory)
        def client = sshd.getConnectedClient(cfg)

        when:
        client.authPublickey(IntegrationTestUtil.USERNAME, IntegrationTestUtil.KEYFILE)

        then:
        client.authenticated

        where:
        kexFactory << [DHGroups.Group1SHA1(),
                       DHGroups.Group14SHA1(),
                       DHGroups.Group14SHA256(),
                       DHGroups.Group16SHA512(),
                       DHGroups.Group18SHA512(),
                       new DHGexSHA1.Factory(),
                       new DHGexSHA256.Factory(),
                       new Curve25519SHA256.Factory(),
                       new Curve25519SHA256.FactoryLibSsh(),
                       new ECDHNistP.Factory256(),
                       new ECDHNistP.Factory384(),
                       new ECDHNistP.Factory521()]
        kex = kexFactory.name
    }

}
