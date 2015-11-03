package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.transport.digest.Digest;
import net.schmizz.sshj.transport.digest.SHA256;
import net.schmizz.sshj.transport.digest.SHA384;
import net.schmizz.sshj.transport.digest.SHA512;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

import java.security.GeneralSecurityException;

public class ECDHNistP extends AbstractDHG {

    private String curve;

    /** Named factory for ECDHNistP key exchange */
    public static class Factory521
            implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        @Override
        public KeyExchange create() {
            return new ECDHNistP("P-521", new SHA512());
        }

        @Override
        public String getName() {
            return "ecdh-sha2-nistp521";
        }
    }

    /** Named factory for ECDHNistP key exchange */
    public static class Factory384
            implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        @Override
        public KeyExchange create() {
            return new ECDHNistP("P-384", new SHA384());
        }

        @Override
        public String getName() {
            return "ecdh-sha2-nistp384";
        }
    }

    /** Named factory for ECDHNistP key exchange */
    public static class Factory256
            implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        @Override
        public KeyExchange create() {
            return new ECDHNistP("P-256", new SHA256());
        }

        @Override
        public String getName() {
            return "ecdh-sha2-nistp256";
        }
    }

    public ECDHNistP(String curve, Digest digest) {
        super(new ECDH(), digest);
        this.curve = curve;
    }

    @Override
    protected void initDH(DHBase dh) throws GeneralSecurityException {
        dh.init(new ECNamedCurveGenParameterSpec(curve));
    }

}
