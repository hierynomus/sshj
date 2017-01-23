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

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import static net.schmizz.sshj.util.gss.BogusGSSManager.unavailable;

public class BogusGSSCredential
        implements GSSCredential {

    private final GSSName name;
    private final int usage;

    public BogusGSSCredential(GSSName name, int usage) {
        this.name = name;
        this.usage = usage;
    }

    @Override
    public void dispose() throws GSSException {
        // Nothing to do
    }

    @Override
    public GSSName getName() throws GSSException {
        return name;
    }

    @Override
    public GSSName getName(Oid mech) throws GSSException {
        return name.canonicalize(mech);
    }

    @Override
    public int getRemainingLifetime() throws GSSException {
        return INDEFINITE_LIFETIME;
    }

    @Override
    public int getRemainingInitLifetime(Oid mech) throws GSSException {
        return INDEFINITE_LIFETIME;
    }

    @Override
    public int getRemainingAcceptLifetime(Oid mech) throws GSSException {
        return INDEFINITE_LIFETIME;
    }

    @Override
    public int getUsage() throws GSSException {
        return usage;
    }

    @Override
    public int getUsage(Oid mech) throws GSSException {
        return usage;
    }

    @Override
    public Oid[] getMechs() throws GSSException {
        return new Oid[] { BogusGSSManager.KRB5_MECH };
    }

    @Override
    public void add(GSSName name, int initLifetime, int acceptLifetime, Oid mech, int usage) throws GSSException {
        throw unavailable();
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    @Override
    public int hashCode() {
        return (name == null ? 0 : name.hashCode());
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof BogusGSSCredential)) {
            return false;
        }
        GSSName otherName = ((BogusGSSCredential) obj).name;
        return name == null ? otherName == null : name.equals((Object) otherName);
    }
}
