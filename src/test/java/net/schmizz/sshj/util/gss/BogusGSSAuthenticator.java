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
