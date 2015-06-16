package net.schmizz.sshj.util.gss;

import static net.schmizz.sshj.util.gss.BogusGSSManager.unavailable;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class BogusGSSCredential
        implements GSSCredential {

    private final GSSName name;
    private final int usage;

    public BogusGSSCredential(GSSName name, int usage) {
        this.name = name;
        this.usage = usage;
    }

    @Override
    public void dispose() throws GSSException {}

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
