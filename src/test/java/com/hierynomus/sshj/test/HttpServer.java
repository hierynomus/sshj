package com.hierynomus.sshj.test;

import org.junit.rules.ExternalResource;
import org.junit.rules.TemporaryFolder;

import java.io.File;

/**
 * Can be used to setup a test HTTP server
 */
public class HttpServer extends ExternalResource {

    private org.glassfish.grizzly.http.server.HttpServer httpServer;

    private TemporaryFolder docRoot = new TemporaryFolder();

    public HttpServer() {
    }

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
