package com.hierynomus.sshj;

import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;

public class IntegrationTest {

    @Test
    public void shouldConnect() throws IOException {
        SSHClient sshClient = new SSHClient(new DefaultConfig());
        sshClient.addHostKeyVerifier(new OpenSSHKnownHosts(new File("/Users/ajvanerp/.ssh/known_hosts")));
        sshClient.connect("172.16.37.129");
        sshClient.authPassword("jeroen", "jeroen");
        assertThat("Is connected", sshClient.isAuthenticated());
    }
}
