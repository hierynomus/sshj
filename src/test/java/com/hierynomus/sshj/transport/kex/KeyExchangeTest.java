package com.hierynomus.sshj.transport.kex;

import com.hierynomus.sshj.test.KnownFailingTests;
import com.hierynomus.sshj.test.SshFixture;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.transport.kex.DHGexSHA1;
import net.schmizz.sshj.transport.kex.DHGexSHA256;
import net.schmizz.sshj.transport.kex.ECDHNistP;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.kex.*;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.io.IOException;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;

public class KeyExchangeTest {
    @Rule
    public SshFixture fixture = new SshFixture(false);

    @After
    public void stopServer() {
        fixture.stopServer();
    }

    @Test
    public void shouldKexWithDiffieHellmanGroupExchangeSha1() throws IOException {
        setupAndCheckKex(new DHGEX.Factory(), new DHGexSHA1.Factory());
    }

    @Test
    public void shouldKexWithDiffieHellmanGroupExchangeSha256() throws IOException {
        setupAndCheckKex(new DHGEX256.Factory(), new DHGexSHA256.Factory());
    }

    @Test
    public void shouldKexWithEllipticCurveDiffieHellmanNistP256() throws IOException {
        setupAndCheckKex(new ECDHP256.Factory(), new ECDHNistP.Factory256());
    }

    @Test
    public void shouldKexWithEllipticCurveDiffieHellmanNistP384() throws IOException {
        setupAndCheckKex(new ECDHP384.Factory(), new ECDHNistP.Factory384());
    }

    @Test
    @Category({KnownFailingTests.class})
    public void shouldKexWithEllipticCurveDiffieHellmanNistP521() throws IOException {
        setupAndCheckKex(new ECDHP521.Factory(), new ECDHNistP.Factory521());
    }

    private void setupAndCheckKex(NamedFactory<KeyExchange> serverFactory,
                                  Factory.Named<net.schmizz.sshj.transport.kex.KeyExchange> clientFactory) throws IOException {
        fixture.getServer().setKeyExchangeFactories(Collections.singletonList(serverFactory));
        fixture.start();
        DefaultConfig config = new DefaultConfig();
        config.setKeyExchangeFactories(Collections.singletonList(clientFactory));
        SSHClient sshClient = fixture.connectClient(fixture.setupClient(config));
        assertThat("should be connected", sshClient.isConnected());
        sshClient.disconnect();
    }
}
