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
package com.hierynomus.sshj.transport;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.ByteArrayUtils;
import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.transport.TransportException;
import org.slf4j.Logger;

import java.io.IOException;
import java.util.Arrays;

public class IdentificationStringParser {
    private final Logger log;
    private final Buffer.PlainBuffer buffer;

    private byte[] EXPECTED_START_BYTES = new byte[] {'S', 'S', 'H', '-'};

    public IdentificationStringParser(Buffer.PlainBuffer buffer) {
	this(buffer, LoggerFactory.DEFAULT);
    }

    public IdentificationStringParser(Buffer.PlainBuffer buffer, LoggerFactory loggerFactory) {
        this.log = loggerFactory.getLogger(IdentificationStringParser.class);
        this.buffer = buffer;
    }

    public String parseIdentificationString() throws IOException {
        for (;;) {
            Buffer.PlainBuffer lineBuffer = new Buffer.PlainBuffer();
            int lineStartPos = buffer.rpos();
            for (;;) {
                if (buffer.available() == 0) {
                    buffer.rpos(lineStartPos);
                    return "";
                }
                byte b = buffer.readByte();
                lineBuffer.putByte(b);
                if (b == '\n') {
                    if (checkForIdentification(lineBuffer)) {
                        return readIdentification(lineBuffer);
                    } else {
                        logHeaderLine(lineBuffer);
                    }
                    break;
                }
            }
        }
    }

    private void logHeaderLine(Buffer.PlainBuffer lineBuffer) throws Buffer.BufferException {
        byte[] bytes = new byte[lineBuffer.available()];
        lineBuffer.readRawBytes(bytes);
        String header = new String(bytes, 0, bytes.length - 1);
        log.debug("Received header: {}", header);
    }

    private String readIdentification(Buffer.PlainBuffer lineBuffer) throws Buffer.BufferException, TransportException {
        byte[] bytes = new byte[lineBuffer.available()];
        lineBuffer.readRawBytes(bytes);
        if (bytes.length > 255) {
            log.error("Incorrect identification String received, line was longer than expected: {}", new String(bytes));
            log.error("Just for good measure, bytes were: {}", ByteArrayUtils.printHex(bytes, 0, bytes.length));
            throw new TransportException("Incorrect identification: line too long: " + ByteArrayUtils.printHex(bytes, 0, bytes.length));
        }
        if (bytes[bytes.length - 2] != '\r') {
            String ident = new String(bytes, 0, bytes.length - 1);
            log.warn("Server identification has bad line ending, was expecting a '\\r\\n' however got: '{}' (hex: {})", (char) (bytes[bytes.length - 2] & 0xFF), Integer.toHexString(bytes[bytes.length - 2] & 0xFF));
            log.warn("Will treat the identification of this server '{}' leniently", ident);
            return ident;
            // log.error("Data received up til here was: {}", new String(bytes));
            // throw new TransportException("Incorrect identification: bad line ending: " + ByteArrayUtils.toHex(bytes, 0, bytes.length));
        }

        // Strip off the \r\n
        return new String(bytes, 0, bytes.length - 2);
    }

    private boolean checkForIdentification(Buffer.PlainBuffer lineBuffer) throws Buffer.BufferException {
        if (lineBuffer.available() < 4) {
            return false;
        }
        byte[] buf = new byte[4];
        lineBuffer.readRawBytes(buf);
        // Reset
        lineBuffer.rpos(0);
        return Arrays.equals(EXPECTED_START_BYTES, buf);
    }
}
