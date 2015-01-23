package nl.javadude.sshj.connection.channel;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;

public class ChannelCloseEofTest {

    private SSHClient sshClient;

    @Before
    public void setUp() throws Exception {
        sshClient = new SSHClient();
    }

    @After
    public void tearDown() throws IOException {
        sshClient.disconnect();
    }

    @Test
    public void shouldCorrectlyHandleSessionChannelEof() throws IOException, InterruptedException {
        sshClient.addHostKeyVerifier(new PromiscuousVerifier());
        sshClient.connect("172.16.37.129");
        sshClient.authPassword("jeroen", "jeroen");
        Session session = sshClient.startSession();
        session.allocateDefaultPTY();
        session.close();
        Thread.sleep(1000);
        assertThat("Should still be connected", sshClient.isConnected());
    }
}
