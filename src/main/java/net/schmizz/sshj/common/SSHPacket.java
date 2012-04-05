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

import java.util.Arrays;

public final class SSHPacket
        extends Buffer<SSHPacket> {

    public SSHPacket() {
        super();
    }

    public SSHPacket(int size) {
        super(size);
    }

    public SSHPacket(byte[] data) {
        super(data);
    }

    /**
     * Constructs new buffer for the specified SSH packet and reserves the needed space (5 bytes) for the packet
     * header.
     *
     * @param msg the SSH command
     */
    public SSHPacket(Message msg) {
        super();
        rpos = wpos = 5;
        putMessageID(msg);
    }

    public SSHPacket(SSHPacket p) {
        this.data = Arrays.copyOf(p.data, p.wpos);
        this.rpos = p.rpos;
        this.wpos = p.wpos;
    }

    /**
     * Reads an SSH byte and returns it as {@link Message}
     *
     * @return the message identifier
     */
    public Message readMessageID()
            throws BufferException {
        return Message.fromByte(readByte());
    }

    /**
     * Writes a byte indicating the SSH message identifier
     *
     * @param msg the identifier as a {@link Message} type
     *
     * @return this
     */
    public SSHPacket putMessageID(Message msg) {
        return putByte(msg.toByte());
    }

}