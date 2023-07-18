/*
 * Copyright (C)2009 - SSHJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.schmizz.sshj.common;

import org.junit.jupiter.api.Test;

import java.io.*;
import java.util.Random;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
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

        org.slf4j.Logger logger = mock(org.slf4j.Logger.class);
        when(loggerFactory.getLogger(StreamCopier.class)).thenReturn(logger);
        StreamCopier streamCopier = new StreamCopier(inputStream, outputStream, loggerFactory);

        long copied = streamCopier.copy();
        assertThat(copied, is(1024L));

        verify(logger).debug(matches("^1[.,]0 KiB transferred.*$"));
    }
}
