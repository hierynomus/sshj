/*
 * Copyright 2010 Shikhar Bhushan
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

/** Disconnect error codes */
public enum DisconnectReason {

    UNKNOWN(0),
    HOST_NOT_ALLOWED_TO_CONNECT(1),
    PROTOCOL_ERROR(2),
    KEY_EXCHANGE_FAILED(3),
    HOST_AUTHENTICATION_FAILED(4),
    RESERVED(4),
    MAC_ERROR(5),
    COMPRESSION_ERROR(6),
    SERVICE_NOT_AVAILABLE(7),
    PROTOCOL_VERSION_NOT_SUPPORTED(8),
    HOST_KEY_NOT_VERIFIABLE(9),
    CONNECTION_LOST(10),
    BY_APPLICATION(11),
    TOO_MANY_CONNECTIONS(12),
    AUTH_CANCELLED_BY_USER(13),
    NO_MORE_AUTH_METHODS_AVAILABLE(14),
    ILLEGAL_USER_NAME(15);

    public static DisconnectReason fromInt(int code) {
        for (DisconnectReason dc : values())
            if (dc.code == code)
                return dc;
        return UNKNOWN;
    }

    private final int code;

    private DisconnectReason(int code) {
        this.code = code;
    }

    public int toInt() {
        return code;
    }

}
