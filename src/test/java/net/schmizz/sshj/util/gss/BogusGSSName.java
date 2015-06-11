package net.schmizz.sshj.util.gss;

import static net.schmizz.sshj.util.gss.BogusGSSManager.unavailable;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

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
