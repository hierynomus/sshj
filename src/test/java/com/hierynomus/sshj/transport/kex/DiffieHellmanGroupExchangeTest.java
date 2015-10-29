package com.hierynomus.sshj.transport.kex;

import com.hierynomus.sshj.test.SshFixture;
import net.schmizz.sshj.SSHClient;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.kex.DHGEX;
import org.apache.sshd.server.kex.DHGEX256;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;

public class DiffieHellmanGroupExchangeTest {
    @Rule
    public SshFixture fixture = new SshFixture(false);

    @After
    public void stopServer() {
        fixture.stopServer();
    }

    @Test
    public void shouldKexWithGroupExchangeSha1() throws IOException {
        setupAndCheckKex(new DHGEX.Factory());
    }

    @Test
    public void shouldKexWithGroupExchangeSha256() throws IOException {
        setupAndCheckKex(new DHGEX256.Factory());
    }

    private void setupAndCheckKex(NamedFactory<KeyExchange> factory) throws IOException {
        fixture.getServer().setKeyExchangeFactories(Collections.singletonList(factory));
        fixture.start();
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        assertThat("should be connected", sshClient.isConnected());
        sshClient.disconnect();
    }
}
