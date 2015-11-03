package com.hierynomus.sshj.transport.kex;

import com.hierynomus.sshj.test.KnownFailingTests;
import com.hierynomus.sshj.test.SshFixture;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.transport.kex.Curve25519SHA256;
import net.schmizz.sshj.transport.kex.DHGexSHA1;
import net.schmizz.sshj.transport.kex.DHGexSHA256;
import net.schmizz.sshj.transport.kex.ECDHNistP;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.server.kex.DHGEXServer;
import org.apache.sshd.server.kex.DHGServer;
import org.junit.After;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;

public class KeyExchangeTest {
    private static final Logger logger = LoggerFactory.getLogger(KeyExchangeTest.class);

    @Rule
    public SshFixture fixture = new SshFixture(false);

    @After
    public void stopServer() {
        fixture.stopServer();
    }

    @Test
    public void shouldKexWithDiffieHellmanGroupExchangeSha1() throws IOException {
        setupAndCheckKex(DHGEXServer.newFactory(BuiltinDHFactories.dhgex), new DHGexSHA1.Factory());
    }

    @Test
    public void shouldKexWithDiffieHellmanGroupExchangeSha256() throws IOException {
        setupAndCheckKex(DHGEXServer.newFactory(BuiltinDHFactories.dhgex256), new DHGexSHA256.Factory());
    }

    @Test
    public void shouldKexWithEllipticCurveDiffieHellmanNistP256() throws IOException {
        attemptKex(100, DHGServer.newFactory(BuiltinDHFactories.ecdhp256), new ECDHNistP.Factory256());
    }

    @Test
    public void shouldKexWithEllipticCurveDiffieHellmanNistP384() throws IOException {
        attemptKex(100, DHGServer.newFactory(BuiltinDHFactories.ecdhp384), new ECDHNistP.Factory384());
    }

    @Test
    public void shouldKexWithEllipticCurveDiffieHellmanNistP521() throws IOException {
        attemptKex(100, DHGServer.newFactory(BuiltinDHFactories.ecdhp521), new ECDHNistP.Factory521());
    }

    @Test
    @Ignore("Apache SSHD does (not yet) have Curve25519 support")
    public void shouldKexWithCurve25519() throws IOException {
        attemptKex(100, null, new Curve25519SHA256.Factory());
    }


    private void attemptKex(int times, NamedFactory<org.apache.sshd.common.kex.KeyExchange> serverFactory,
                            Factory.Named<net.schmizz.sshj.transport.kex.KeyExchange> clientFactory) throws IOException {
        for (int i = 0; i < times; i++) {
            logger.info("--> Attempt {}", i);
            setupAndCheckKex(serverFactory, clientFactory);
        }
    }

    private void setupAndCheckKex(NamedFactory<org.apache.sshd.common.kex.KeyExchange> serverFactory,
                                  Factory.Named<net.schmizz.sshj.transport.kex.KeyExchange> clientFactory) throws IOException {
        fixture.getServer().setKeyExchangeFactories(Collections.singletonList(serverFactory));
        fixture.start();
        DefaultConfig config = new DefaultConfig();
        config.setKeyExchangeFactories(Collections.singletonList(clientFactory));
        SSHClient sshClient = fixture.connectClient(fixture.setupClient(config));
        assertThat("should be connected", sshClient.isConnected());
        sshClient.disconnect();
//        fixture.stopServer();
        fixture.stopClient();
    }
}
