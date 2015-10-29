package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.transport.digest.SHA256;

public class DHGexSHA256 extends AbstractDHGex {

    /** Named factory for DHGexSHA256 key exchange */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        @Override
        public KeyExchange create() {
            return new DHGexSHA256();
        }

        @Override
        public String getName() {
            return "diffie-hellman-group-exchange-sha256";
        }
    }

    public DHGexSHA256() {
        super(new SHA256());
    }
}
