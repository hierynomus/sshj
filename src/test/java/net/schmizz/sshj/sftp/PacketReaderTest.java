package net.schmizz.sshj.sftp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.DataOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Arrays;

import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.connection.channel.direct.Session.Subsystem;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class PacketReaderTest {

    private DataOutputStream dataout;
    private PacketReader reader;
    private SFTPEngine engine;
    private Subsystem subsystem;

    @Before
    public void setUp() throws Exception {
        PipedOutputStream pipedout = new PipedOutputStream();
        PipedInputStream pipedin = new PipedInputStream(pipedout);
        dataout = new DataOutputStream(pipedout);

        engine = Mockito.mock(SFTPEngine.class);
        subsystem = Mockito.mock(Subsystem.class);
        Mockito.when(engine.getSubsystem()).thenReturn(subsystem);
        Mockito.when(subsystem.getInputStream()).thenReturn(pipedin);

        reader = new PacketReader(engine);
    }

    // FIXME What is the byte format for the size? Big endian? Little endian?
    @Test
    public void shouldReadPacket() throws Exception {
        byte[] bytes = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        dataout.writeInt(10);
        dataout.write(bytes);
        dataout.flush();
        
        SFTPPacket<Response> packet = reader.readPacket();
        assertEquals(packet.available(), 10);
        assertTrue("actual=" + Arrays.toString(packet.array()), Arrays.equals(bytes, subArray(packet.array(), 0, 10)));
    }

    @Test
    public void shouldFailWhenPacketLengthTooLarge() throws Exception {
        dataout.writeInt(Integer.MAX_VALUE);
        dataout.flush();
        
        try {
            reader.readPacket();
            fail("Should have failed to read packet of size " + Integer.MAX_VALUE);
        } catch (SSHException e) {
            e.printStackTrace();
            // success; indicated packet size was too large
        }
    }

    private byte[] subArray(byte[] source, int startIndex, int length) {
        byte[] result = new byte[length];
        System.arraycopy(source, startIndex, result, 0, length);
        return result;
    }
}
