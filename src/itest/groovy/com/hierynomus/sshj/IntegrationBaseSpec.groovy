package com.hierynomus.sshj

import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.transport.verification.PromiscuousVerifier
import spock.lang.Specification

class IntegrationBaseSpec extends Specification {
    protected static final int DOCKER_PORT = 2222;
    protected static final String USERNAME = "sshj";
    protected final static String SERVER_IP = System.getProperty("serverIP", "127.0.0.1");

    protected static SSHClient getConnectedClient() throws IOException {
        SSHClient sshClient = new SSHClient(new DefaultConfig());
        sshClient.addHostKeyVerifier(new PromiscuousVerifier());
        sshClient.connect(SERVER_IP, DOCKER_PORT);

        return sshClient;
    }

}
