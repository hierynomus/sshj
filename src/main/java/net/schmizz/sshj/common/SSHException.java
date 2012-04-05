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
 *
 * This file may incorporate work covered by the following copyright and
 * permission notice:
 *
 *     Licensed to the Apache Software Foundation (ASF) under one
 *     or more contributor license agreements.  See the NOTICE file
 *     distributed with this work for additional information
 *     regarding copyright ownership.  The ASF licenses this file
 *     to you under the Apache License, Version 2.0 (the
 *     "License"); you may not use this file except in compliance
 *     with the License.  You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing,
 *      software distributed under the License is distributed on an
 *      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *      KIND, either express or implied.  See the License for the
 *      specific language governing permissions and limitations
 *      under the License.
 */
package net.schmizz.sshj.common;

import net.schmizz.concurrent.ExceptionChainer;

import java.io.IOException;

/**
 * Most exceptions in the {@code net.schmizz.sshj} package are instances of this class. An {@link SSHException} is
 * itself an {@link IOException} and can be caught like that if this level of granularity is not desired.
 */
public class SSHException
        extends IOException {

    public static final ExceptionChainer<SSHException> chainer = new ExceptionChainer<SSHException>() {

        @Override
        public SSHException chain(Throwable t) {
            if (t instanceof SSHException)
                return (SSHException) t;
            else
                return new SSHException(t);
        }

    };

    private final DisconnectReason reason;

    public SSHException(DisconnectReason code) {
        this(code, null, null);
    }

    public SSHException(DisconnectReason code, String message) {
        this(code, message, null);
    }

    public SSHException(DisconnectReason code, String message, Throwable cause) {
        super(message);
        this.reason = code;
        if (cause != null)
            initCause(cause);
    }

    public SSHException(DisconnectReason code, Throwable cause) {
        this(code, null, cause);
    }

    public SSHException(String message) {
        this(DisconnectReason.UNKNOWN, message, null);
    }

    public SSHException(String message, Throwable cause) {
        this(DisconnectReason.UNKNOWN, message, cause);
    }

    public SSHException(Throwable cause) {
        this(DisconnectReason.UNKNOWN, null, cause);
    }

    public DisconnectReason getDisconnectReason() {
        return reason;
    }

    @Override
    public String getMessage() {
        if (super.getMessage() != null)
            return super.getMessage();
        else if (getCause() != null && getCause().getMessage() != null)
            return getCause().getMessage();
        else
            return null;
    }

    @Override
    public String toString() {
        final String cls = getClass().getName();
        final String code = reason != DisconnectReason.UNKNOWN ? "[" + reason + "] " : "";
        final String msg = getMessage() != null ? getMessage() : "";
        return cls + (code.isEmpty() && msg.isEmpty() ? "" : ": ") + code + msg;
    }

}
