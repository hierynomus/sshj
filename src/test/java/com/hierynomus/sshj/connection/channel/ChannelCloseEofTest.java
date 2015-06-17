package com.hierynomus.sshj.connection.channel;

import com.hierynomus.sshj.SshFixture;
import net.schmizz.sshj.connection.channel.direct.Session;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;

public class ChannelCloseEofTest {

    @Rule
    public SshFixture fixture = new SshFixture();

    @Test
    public void shouldCorrectlyHandleSessionChannelEof() throws IOException, InterruptedException {
        fixture.setupConnectedDefaultClient().authPassword("jeroen", "jeroen");
        Session session = fixture.getClient().startSession();
        session.allocateDefaultPTY();
        session.close();
        Thread.sleep(1000);
        assertThat("Should still be connected", fixture.getClient().isConnected());
    }

}
