package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.*;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.digest.SHA256;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;

public class Curve25519SHA256 extends AbstractDHG {
    private static final Logger logger = LoggerFactory.getLogger(Curve25519SHA256.class);

    /** Named factory for Curve25519SHA256 key exchange */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        @Override
        public KeyExchange create() {
            return new Curve25519SHA256();
        }

        @Override
        public String getName() {
            return "curve25519-sha256@libssh.org";
        }
    }

    public Curve25519SHA256() {
        super(new Curve25519DH(), new SHA256());
    }

    @Override
    protected void initDH(DHBase dh) throws GeneralSecurityException {
        dh.init(Curve25519DH.getCurve25519Params());
    }
}
