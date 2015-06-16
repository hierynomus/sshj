package net.schmizz.sshj.util.gss;

import java.security.Provider;

import org.apache.sshd.server.auth.gss.UserAuthGSS;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements a fake Kerberos 5 mechanism. MINA only supports Kerberos 5 over
 * GSS-API, so we can't implement a separate mechanism.
 */
public class BogusGSSManager
        extends GSSManager {

    public static final Oid KRB5_MECH = UserAuthGSS.KRB5_MECH;

    private static final Logger log = LoggerFactory.getLogger(BogusGSSManager.class);

    @Override
    public Oid[] getMechs() {
        return new Oid[] { KRB5_MECH };
    }

    @Override
    public Oid[] getNamesForMech(Oid mech) throws GSSException {
        return new Oid[] { GSSName.NT_EXPORT_NAME, GSSName.NT_HOSTBASED_SERVICE };
    }

    @Override
    public Oid[] getMechsForName(Oid nameType) {
        return new Oid[] { KRB5_MECH };
    }

    @Override
    public GSSName createName(String nameStr, Oid nameType) throws GSSException {
        return new BogusGSSName(nameStr, nameType);
    }

    @Override
    public GSSName createName(byte[] name, Oid nameType) throws GSSException {
        throw unavailable();
    }

    @Override
    public GSSName createName(String nameStr, Oid nameType, Oid mech) throws GSSException {
        return this.createName(nameStr, nameType);
    }

    @Override
    public GSSName createName(byte[] name, Oid nameType, Oid mech) throws GSSException {
        throw unavailable();
    }

    @Override
    public GSSCredential createCredential(int usage) throws GSSException {
        return new BogusGSSCredential(null, usage);
    }

    @Override
    public GSSCredential createCredential(GSSName name, int lifetime, Oid mech, int usage) throws GSSException {
        return new BogusGSSCredential(name, usage);
    }

    @Override
    public GSSCredential createCredential(GSSName name, int lifetime, Oid[] mechs, int usage) throws GSSException {
        return new BogusGSSCredential(name, usage);
    }

    @Override
    public GSSContext createContext(GSSName peer, Oid mech, GSSCredential myCred, int lifetime) throws GSSException {
        return new BogusGSSContext();
    }

    @Override
    public GSSContext createContext(GSSCredential myCred) throws GSSException {
        return new BogusGSSContext();
    }

    @Override
    public GSSContext createContext(byte[] interProcessToken) throws GSSException {
        throw unavailable();
    }

    @Override
    public void addProviderAtFront(Provider p, Oid mech) throws GSSException {
        throw unavailable();
    }

    @Override
    public void addProviderAtEnd(Provider p, Oid mech) throws GSSException {
        throw unavailable();
    }

    static GSSException unavailable() throws GSSException {
        GSSException e = new GSSException(GSSException.UNAVAILABLE);
        log.error(e.getMessage(), e);
        throw e;
    }
}