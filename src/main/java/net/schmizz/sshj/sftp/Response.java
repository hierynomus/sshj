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

import net.schmizz.sshj.common.Buffer;

public final class Response
        extends SFTPPacket<Response> {

    public enum StatusCode {
        UNKNOWN(-1),
        OK(0),
        EOF(1),
        NO_SUCH_FILE(2),
        PERMISSION_DENIED(3),
        FAILURE(4),
        BAD_MESSAGE(5),
        NO_CONNECTION(6),
        CONNECITON_LOST(7),
        OP_UNSUPPORTED(8),
        INVALID_HANDLE(9),
        NO_SUCH_PATH(10),
        FILE_ALREADY_EXISTS(11),
        WRITE_PROTECT(12),
        NO_MEDIA(13),
        NO_SPACE_ON_FILESYSTEM(14),
        QUOTA_EXCEEDED(15),
        UNKNOWN_PRINCIPAL(16),
        LOCK_CONFLICT(17),
        DIR_NOT_EMPTY(18),
        NOT_A_DIRECTORY(19),
        INVALID_FILENAME(20),
        LINK_LOOP(21),
        CANNOT_DELETE(22),
        INVALID_PARAMETER(23),
        FILE_IS_A_DIRECTORY(24),
        BYTE_RANGE_LOCK_CONFLICT(25),
        BYTE_RANGE_LOCK_REFUSED(26),
        DELETE_PENDING(27),
        FILE_CORRUPT(28),
        OWNER_INVALID(29),
        GROUP_INVALID(30),
        NO_MATCHING_BYTE_RANGE_LOCK(31);

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

        public int getCode() {
            return code;
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

    @SuppressWarnings("PMD.CompareObjectsWithEquals")
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
