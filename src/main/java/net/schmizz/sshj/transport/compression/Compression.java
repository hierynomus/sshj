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
package net.schmizz.sshj.transport.compression;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.transport.TransportException;

/** Interface used to compress the stream of data between the SSH server and clients. */
public interface Compression {

    /** Enum identifying if this object will be used to compress or uncompress data. */
    enum Mode {
        INFLATE,
        DEFLATE
    }

    /**
     * Initialize this object to either compress or uncompress data. This method must be called prior to any calls to
     * either <code>compress</code> or <code>uncompress</code>. Once the object has been initialized, only one of
     * <code>compress</code> or <code>uncompress</code> method can be called.
     *
     * @param mode
     */
    void init(Mode mode);

    /**
     * Delayed compression is an Open-SSH specific feature which informs both the client and server to not compress data
     * before the session has been authenticated.
     *
     * @return if the compression is delayed after authentication or not
     */
    boolean isDelayed();

    /**
     * Compress the given buffer in place.
     *
     * @param buffer the buffer containing the data to compress s
     */
    void compress(Buffer buffer);

    /**
     * Uncompress the data in a buffer into another buffer.
     *
     * @param from the buffer containing the data to uncompress
     * @param to   the buffer receiving the uncompressed data
     *
     * @throws TransportException
     */
    void uncompress(Buffer from, Buffer to)
            throws TransportException;

}
