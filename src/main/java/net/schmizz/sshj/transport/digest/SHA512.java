package net.schmizz.sshj.transport.digest;

public class SHA512 extends BaseDigest {
/** Named factory for SHA384 digest */
public static class Factory
        implements net.schmizz.sshj.common.Factory.Named<Digest> {

    @Override
    public Digest create() {
        return new SHA512();
    }

    @Override
    public String getName() {
        return "sha512";
    }
}

    /** Create a new instance of a SHA384 digest */
    public SHA512() {
        super("SHA-512", 64);
    }
}
