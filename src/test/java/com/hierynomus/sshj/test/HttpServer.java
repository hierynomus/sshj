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

import org.junit.rules.ExternalResource;
import org.junit.rules.TemporaryFolder;

/**
 * Can be used to setup a test HTTP server
 */
public class HttpServer extends ExternalResource {

    private org.glassfish.grizzly.http.server.HttpServer httpServer;

    private TemporaryFolder docRoot = new TemporaryFolder();

    @Override
    protected void before() throws Throwable {
        docRoot.create();
        httpServer = org.glassfish.grizzly.http.server.HttpServer.createSimpleServer(docRoot.getRoot().getAbsolutePath());
        httpServer.start();
    }

    @Override
    protected void after() {
        try {
            httpServer.shutdownNow();
        } catch (Exception e) {}
        try {
            docRoot.delete();
        } catch (Exception e) {}

    }

    public org.glassfish.grizzly.http.server.HttpServer getHttpServer() {
        return httpServer;
    }

    public TemporaryFolder getDocRoot() {
        return docRoot;
    }
}
