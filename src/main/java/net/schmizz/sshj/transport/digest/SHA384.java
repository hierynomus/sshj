package net.schmizz.sshj.transport.digest;

public class SHA384 extends BaseDigest {
/** Named factory for SHA384 digest */
public static class Factory
        implements net.schmizz.sshj.common.Factory.Named<Digest> {

    @Override
    public Digest create() {
        return new SHA384();
    }

    @Override
    public String getName() {
        return "sha384";
    }
}

    /** Create a new instance of a SHA384 digest */
    public SHA384() {
        super("SHA-384", 48);
    }
}
