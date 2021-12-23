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
package com.hierynomus.sshj.common;

import java.net.InetSocketAddress;

public class ThreadNameProvider {
    private static final String DISCONNECTED = "DISCONNECTED";

    /**
     * Set Thread Name prefixed with sshj followed by class and remote address when connected
     *
     * @param thread Class of Thread being named
     * @param remoteAddressProvider Remote Address Provider associated with Thread
     */
    public static void setThreadName(final Thread thread, final RemoteAddressProvider remoteAddressProvider) {
        final InetSocketAddress remoteSocketAddress = remoteAddressProvider.getRemoteSocketAddress();
        final String address = remoteSocketAddress == null ? DISCONNECTED : remoteSocketAddress.toString();
        final String threadName = String.format("sshj-%s-%s", thread.getClass().getSimpleName(), address);
        thread.setName(threadName);
    }
}
