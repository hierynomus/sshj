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
package com.hierynomus.sshj.userauth.fido;

/**
 * {@link SecurityKeySigner}s backed by a {@link SoftwareSecurityKeyMiddleware}: what an application
 * embedding a security key middleware would write.
 */
public final class SecurityKeyTestSigners {

    private SecurityKeyTestSigners() {
    }

    /**
     * Calls the middleware the way it is meant to be called: with the data to sign, from which the
     * middleware derives the client-data hash itself.
     */
    public static SecurityKeySigner middlewareSigner(SoftwareSecurityKeyMiddleware middleware, boolean ed25519) {
        return request -> toSignatureData(
                middleware.sign(request.getData(), request.getApplication(), request.getKeyHandle(), request.getMinFlags()),
                ed25519);
    }

    /**
     * Calls the middleware with the challenge, as if it were the message. This is the mistake the
     * request used to invite, as it offered no other input: the middleware hashes it again, so the
     * signature does not verify.
     */
    public static SecurityKeySigner challengeForwardingSigner(SoftwareSecurityKeyMiddleware middleware, boolean ed25519) {
        return request -> toSignatureData(
                middleware.sign(request.getChallenge(), request.getApplication(), request.getKeyHandle(), request.getMinFlags()),
                ed25519);
    }

    private static SecurityKeySignatureData toSignatureData(SoftwareSecurityKeyMiddleware.Response response, boolean ed25519) {
        return ed25519
                ? SecurityKeySignatureData.ed25519(response.getFlags(), response.getCounter(), response.getSigR())
                : SecurityKeySignatureData.ecdsa(response.getFlags(), response.getCounter(), response.getSigR(), response.getSigS());
    }
}
