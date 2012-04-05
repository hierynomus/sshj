/*
 * Copyright 2010-2012 sshj contributors
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

import net.schmizz.sshj.common.Buffer;

public final class Response
        extends SFTPPacket<Response> {

    public static enum StatusCode {
        UNKNOWN(-1),
        OK(0),
        EOF(1),
        NO_SUCH_FILE(2),
        PERMISSION_DENIED(3),
        FAILURE(4),
        BAD_MESSAGE(5),
        NO_CONNECTION(6),
        CONNECITON_LOST(7),
        OP_UNSUPPORTED(8);

        private final int code;

        public static StatusCode fromInt(int code) {
            for (StatusCode s : StatusCode.values())
                if (s.code == code)
                    return s;
            return UNKNOWN;
        }

        private StatusCode(int code) {
            this.code = code;
        }

    }

    private final int protocolVersion;
    private final PacketType type;
    private final long reqID;

    public Response(Buffer<Response> pk, int protocolVersion)
            throws SFTPException {
        super(pk);
        this.protocolVersion = protocolVersion;
        this.type = readType();
        try {
            this.reqID = readUInt32();
        } catch (BufferException be) {
            throw new SFTPException(be);
        }
    }

    public int getProtocolVersion() {
        return protocolVersion;
    }

    public long getRequestID() {
        return reqID;
    }

    public PacketType getType() {
        return type;
    }

    public StatusCode readStatusCode()
            throws SFTPException {
        try {
            return StatusCode.fromInt(readUInt32AsInt());
        } catch (BufferException be) {
            throw new SFTPException(be);
        }
    }

    public Response ensurePacketTypeIs(PacketType pt)
            throws SFTPException {
        if (getType() != pt)
            if (getType() == PacketType.STATUS)
                error(readStatusCode());
            else
                throw new SFTPException("Unexpected packet " + getType());
        return this;
    }

    public Response ensureStatusPacketIsOK()
            throws SFTPException {
        return ensurePacketTypeIs(PacketType.STATUS).ensureStatusIs(StatusCode.OK);
    }

    public Response ensureStatusIs(StatusCode acceptable)
            throws SFTPException {
        final StatusCode sc = readStatusCode();
        if (sc != acceptable)
            error(sc);
        return this;
    }

    protected String error(StatusCode sc)
            throws SFTPException {
        try {
            throw new SFTPException(sc, protocolVersion < 3 ? sc.toString() : readString());
        } catch (BufferException be) {
            throw new SFTPException(be);
        }
    }

}
