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
package net.schmizz.sshj.util.gss;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import static net.schmizz.sshj.util.gss.BogusGSSManager.unavailable;

public class BogusGSSName
        implements GSSName {

    private final String name;
    private final Oid oid;

    public BogusGSSName(String name, Oid oid) {
        this.name = name;
        this.oid = oid;
    }

    @Override
    public boolean equals(GSSName another) throws GSSException {
        if (!(another instanceof BogusGSSName)) {
            throw new GSSException(GSSException.BAD_NAMETYPE);
        }
        BogusGSSName otherName = (BogusGSSName) another;
        return name.equals(otherName.name) && oid.equals(otherName.oid);
    }

    @Override
    public GSSName canonicalize(Oid mech) throws GSSException {
        return this;
    }

    @Override
    public byte[] export() throws GSSException {
        throw unavailable();
    }

    @Override
    public Oid getStringNameType() throws GSSException {
        return oid;
    }

    @Override
    public boolean isAnonymous() {
        return false;
    }

    @Override
    public boolean isMN() {
        return false;
    }

    @Override
    public String toString() {
        return name;
    }
}
