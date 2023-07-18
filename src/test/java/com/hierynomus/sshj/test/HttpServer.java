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

import java.io.File;
import java.nio.file.Files;

/**
 * Can be used to setup a test HTTP server
 */
public class HttpServer implements BeforeEachCallback, AfterEachCallback {

    private org.glassfish.grizzly.http.server.HttpServer httpServer;


    private File docRoot ;

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        try {
            httpServer.shutdownNow();
        } catch (Exception e) {}
        try {
            docRoot.delete();
        } catch (Exception e) {}

    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        docRoot = Files.createTempDirectory("sshj").toFile();
        httpServer = org.glassfish.grizzly.http.server.HttpServer.createSimpleServer(docRoot.getAbsolutePath());
        httpServer.start();
    }

    public org.glassfish.grizzly.http.server.HttpServer getHttpServer() {
        return httpServer;
    }

    public File getDocRoot() {
        return docRoot;
    }
}
