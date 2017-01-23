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
package net.schmizz.sshj.sftp;

import net.schmizz.concurrent.Promise;
import net.schmizz.sshj.common.SSHException;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class PacketReader extends Thread {

    /**
     * Logger
     */
    private final Logger log;

    private final InputStream in;
    private final Map<Long, Promise<Response, SFTPException>> promises = new ConcurrentHashMap<Long, Promise<Response, SFTPException>>();
    private final SFTPPacket<Response> packet = new SFTPPacket<Response>();
    private final byte[] lenBuf = new byte[4];
    private final SFTPEngine engine;

    public PacketReader(SFTPEngine engine) {
        this.engine = engine;
        log = engine.getLoggerFactory().getLogger(getClass());
        this.in = engine.getSubsystem().getInputStream();
        setName("sftp reader");
    }

    private void readIntoBuffer(byte[] buf, int off, int len)
            throws IOException {
        int count = 0;
        int read = 0;
        while (count < len && ((read = in.read(buf, off + count, len - count)) != -1))
            count += read;
        if (read == -1)
            throw new SFTPException("EOF while reading packet");
    }

    private int getPacketLength()
            throws IOException {
        readIntoBuffer(lenBuf, 0, lenBuf.length);

        final long len = (lenBuf[0] << 24 & 0xff000000L
                | lenBuf[1] << 16 & 0x00ff0000L
                | lenBuf[2] << 8 & 0x0000ff00L
                | lenBuf[3] & 0x000000ffL);

        if (len > SFTPPacket.MAX_SIZE) {
            throw new SSHException(String.format("Indicated packet length %d too large", len));
        }

        return (int) len;
    }

    public SFTPPacket<Response> readPacket()
            throws IOException {
        final int len = getPacketLength();
        packet.clear();
        packet.ensureCapacity(len);
        readIntoBuffer(packet.array(), 0, len);
        packet.wpos(len);
        return packet;
    }

    @Override
    public void run() {
        try {
            while (!isInterrupted()) {
                readPacket();
                handle();
            }
        } catch (IOException e) {
            for (Promise<Response, SFTPException> promise : promises.values())
                promise.deliverError(e);
        }
    }

    public void handle()
            throws SFTPException {
        Response resp = new Response(packet, engine.getOperativeProtocolVersion());
        Promise<Response, SFTPException> promise = promises.remove(resp.getRequestID());
        log.debug("Received {} packet", resp.getType());
        if (promise == null)
            throw new SFTPException("Received [" + resp.readType() + "] response for request-id " + resp.getRequestID()
                    + ", no such request was made");
        else
            promise.deliver(resp);
    }

    public Promise<Response, SFTPException> expectResponseTo(long requestId) {
        final Promise<Response, SFTPException> promise
                = new Promise<Response, SFTPException>("sftp / " + requestId, SFTPException.chainer, engine.getLoggerFactory());
        promises.put(requestId, promise);
        return promise;
    }

}
