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
package com.hierynomus.sshj.signature;

import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import net.schmizz.sshj.common.SSHRuntimeException;

import java.util.Arrays;

/**
 * Our own extension of the EdDSAPublicKey that comes from ECC-25519, as that class does not implement equality.
 * The code uses the equality of the keys as an indicator whether they're the same during host key verification.
 */
public class Ed25519PublicKey extends EdDSAPublicKey {

    public Ed25519PublicKey(EdDSAPublicKeySpec spec) {
        super(spec);

        EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName("Ed25519");
        if (!spec.getParams().getCurve().equals(ed25519.getCurve())) {
            throw new SSHRuntimeException("Cannot create Ed25519 Public Key from wrong spec");
        }
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Ed25519PublicKey)) {
            return false;
        }

        Ed25519PublicKey otherKey = (Ed25519PublicKey) other;
        return Arrays.equals(getAbyte(), otherKey.getAbyte());
    }

    @Override
    public int hashCode() {
        return getA().hashCode();
    }
}
