package net.schmizz.sshj.transport.digest;

/** SHA256 Digest. */
public class SHA256 extends BaseDigest {

    /** Named factory for SHA256 digest */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Digest> {

        @Override
        public Digest create() {
            return new SHA256();
        }

        @Override
        public String getName() {
            return "sha256";
        }
    }

    /** Create a new instance of a SHA256 digest */
    public SHA256() {
        super("SHA-256", 32);
    }

}
