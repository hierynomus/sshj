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
package com.hierynomus.sshj.test;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.net.InetSocketAddress;
import java.net.URI;

/**
 * Can be used to setup a test HTTP server
 */
public class HttpServer implements BeforeEachCallback, AfterEachCallback {

    private static final String BIND_ADDRESS = "127.0.0.1";

    private com.sun.net.httpserver.HttpServer httpServer;

    @Override
    public void afterEach(ExtensionContext context) {
        try {
            httpServer.stop(0);
        } catch (Exception ignored) {}
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        httpServer = com.sun.net.httpserver.HttpServer.create();
        final InetSocketAddress socketAddress = new InetSocketAddress(BIND_ADDRESS, 0);
        httpServer.bind(socketAddress, 10);
        httpServer.start();
    }

    public URI getServerUrl() {
        final InetSocketAddress bindAddress = httpServer.getAddress();
        final String serverUrl = String.format("http://%s:%d", BIND_ADDRESS, bindAddress.getPort());
        return URI.create(serverUrl);
    }
}
