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
package com.hierynomus.sshj.userauth.agent;

import java.security.PublicKey;

/**
 * An identity held by an SSH agent: a public key, its exact wire encoding (the "key blob" that must
 * be sent back verbatim in a sign request) and the human-readable comment.
 */
public class AgentIdentity {

    private final PublicKey publicKey;
    private final byte[] keyBlob;
    private final String comment;

    public AgentIdentity(PublicKey publicKey, byte[] keyBlob, String comment) {
        this.publicKey = publicKey;
        this.keyBlob = keyBlob;
        this.comment = comment;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    /** @return the exact key blob bytes as returned by the agent. */
    public byte[] getKeyBlob() {
        return keyBlob.clone();
    }

    public String getComment() {
        return comment;
    }

    @Override
    public String toString() {
        return "AgentIdentity{" + comment + ", " + publicKey.getAlgorithm() + "}";
    }
}
