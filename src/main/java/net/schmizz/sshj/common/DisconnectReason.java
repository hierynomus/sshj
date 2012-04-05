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
package net.schmizz.sshj.common;

/** Disconnect error codes */
public enum DisconnectReason {

    UNKNOWN,
    HOST_NOT_ALLOWED_TO_CONNECT,
    PROTOCOL_ERROR,
    KEY_EXCHANGE_FAILED,
    RESERVED,
    MAC_ERROR,
    COMPRESSION_ERROR,
    SERVICE_NOT_AVAILABLE,
    PROTOCOL_VERSION_NOT_SUPPORTED,
    HOST_KEY_NOT_VERIFIABLE,
    CONNECTION_LOST,
    BY_APPLICATION,
    TOO_MANY_CONNECTIONS,
    AUTH_CANCELLED_BY_USER,
    NO_MORE_AUTH_METHODS_AVAILABLE,
    ILLEGAL_USER_NAME;

    public static DisconnectReason fromInt(int code) {
        final int len = values().length;
        if (code < 0 || code > len)
            return UNKNOWN;
        return values()[code];
    }

    public int toInt() {
        return ordinal();
    }

}
