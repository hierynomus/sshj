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
package net.schmizz.sshj.connection.channel;

import net.schmizz.sshj.connection.ConnectionException;

public class OpenFailException
        extends ConnectionException {

    public enum Reason {
        UNKNOWN(0),
        ADMINISTRATIVELY_PROHIBITED(1),
        CONNECT_FAILED(2),
        UNKNOWN_CHANNEL_TYPE(3),
        RESOURCE_SHORTAGE(4);

        public static Reason fromInt(int code) {
            for (Reason rc : Reason.values())
                if (rc.code == code)
                    return rc;
            return UNKNOWN;
        }

        private final int code;

        private Reason(int rc) {
            this.code = rc;
        }

        public int getCode() {
            return code;
        }

    }

    private final String channelType;
    private final Reason reason;
    private final String message;

    public OpenFailException(String channelType, int reasonCode, String message) {
        super(message);
        this.channelType = channelType;
        this.reason = Reason.fromInt(reasonCode);
        this.message = message;
    }

    public OpenFailException(String channelType, Reason reason, String message) {
        super(message);
        this.channelType = channelType;
        this.reason = reason;
        this.message = message;
    }

    public String getChannelType() {
        return channelType;
    }

    @Override
    public String getMessage() {
        return message;
    }

    public Reason getReason() {
        return reason;
    }

    @Override
    public String toString() {
        return "Opening `" + channelType + "` channel failed: " + getMessage();
    }

}