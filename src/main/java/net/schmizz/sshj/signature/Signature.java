/*
 * Copyright 2010 Shikhar Bhushan
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
package net.schmizz.sshj.signature;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Signature interface for SSH used to sign or verify data.
 * <p/>
 * Usually wraps a javax.crypto.Signature object.
 */
public interface Signature {

    /**
     * Initialize this signature with the given public key and private key. If the private key is null, only signature
     * verification can be performed.
     *
     * @param pubkey (null-ok) specify in case verification is needed
     * @param prvkey (null-ok) specify in case signing is needed
     */
    void init(PublicKey pubkey, PrivateKey prvkey);

    /**
     * Compute the signature
     *
     * @return the computed signature
     */
    byte[] sign();

    /**
     * Convenience method for {@link #update(byte[], int, int)}
     *
     * @param H the byte-array to update with
     */
    void update(byte[] H);

    /**
     * Update the computed signature with the given data
     *
     * @param H   byte-array to update with
     * @param off offset within the array
     * @param len length until which to compute
     */
    void update(byte[] H, int off, int len);

    /**
     * Verify against the given signature
     *
     * @param sig
     *
     * @return {@code true} on successful verification, {@code false} on failure
     */
    boolean verify(byte[] sig);

}
