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

import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;

public class BogusGSSAuthenticator
        extends GSSAuthenticator {

    private final GSSManager manager = new BogusGSSManager();

    @Override
    public GSSManager getGSSManager() {
        return manager;
    }

    @Override
    public GSSCredential getGSSCredential(GSSManager mgr) throws GSSException {
        return manager.createCredential(GSSCredential.ACCEPT_ONLY);
    }
}
