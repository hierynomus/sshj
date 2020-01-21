package net.schmizz.sshj.common;


import org.junit.Test;

import java.io.*;
import java.util.Random;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;


public class StreamCopierTest {

    @Test
    public void copy() throws IOException {
        Random random = new Random();
        byte[] data = new byte[1024];
        random.nextBytes(data);
        InputStream inputStream = new ByteArrayInputStream(data);

        OutputStream outputStream = new ByteArrayOutputStream();
        LoggerFactory loggerFactory = mock(LoggerFactory.class);

        org.slf4j.Logger logger= mock(org.slf4j.Logger.class);
        when(loggerFactory.getLogger(StreamCopier.class)).thenReturn(logger);
        StreamCopier streamCopier = new StreamCopier(inputStream,outputStream,loggerFactory);

        long copied =streamCopier.copy();
        assertThat(copied,is(1024l));

        verify(logger).debug(contains("1.0 KiB transferred"));
    }
}
