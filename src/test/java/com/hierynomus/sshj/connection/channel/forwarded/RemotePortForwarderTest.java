package com.hierynomus.sshj.connection.channel.forwarded;

import com.hierynomus.sshj.test.HttpServer;
import com.hierynomus.sshj.test.SshFixture;
import com.hierynomus.sshj.test.util.FileUtil;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder;
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;

import static org.junit.Assert.*;

public class RemotePortForwarderTest {

    @Rule
    public SshFixture fixture = new SshFixture();

    @Rule
    public HttpServer httpServer = new HttpServer();

    @Test
    public void shouldDynamicallyForwardPort() throws IOException {
        fixture.getServer().setTcpipForwardingFilter(new AcceptAllForwardingFilter());
        File file = httpServer.getDocRoot().newFile("index.html");
        FileUtil.writeToFile(file, "<html><head/><body><h1>Hi!</h1></body></html>");
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("jeroen", "jeroen");
        sshClient.getRemotePortForwarder().bind(
                // where the server should listen
                new RemotePortForwarder.Forward(0),
                // what we do with incoming connections that are forwarded to us
                new SocketForwardingConnectListener(new InetSocketAddress("127.0.0.1", 8080)));

    }
}
