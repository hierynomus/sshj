package com.hierynomus.sshj.transport.kex

import com.hierynomus.sshj.IntegrationBaseSpec
import com.hierynomus.sshj.transport.mac.Macs
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.transport.kex.Curve25519DH
import net.schmizz.sshj.transport.kex.Curve25519SHA256
import net.schmizz.sshj.transport.kex.DH
import net.schmizz.sshj.transport.kex.DHGexSHA1
import net.schmizz.sshj.transport.kex.DHGexSHA256
import net.schmizz.sshj.transport.kex.ECDH
import net.schmizz.sshj.transport.kex.ECDHNistP
import spock.lang.Unroll

class KexSpec extends IntegrationBaseSpec {

    @Unroll
    def "should correctly connect with #kex Key Exchange"() {
        given:
        def cfg = new DefaultConfig()
        cfg.setKeyExchangeFactories(kexFactory)
        def client = getConnectedClient(cfg)

        when:
        client.authPublickey(USERNAME, KEYFILE)

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
