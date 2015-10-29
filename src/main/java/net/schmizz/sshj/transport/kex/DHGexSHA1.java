package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.transport.digest.SHA1;

public class DHGexSHA1 extends AbstractDHGex {

    /** Named factory for DHGexSHA1 key exchange */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        @Override
        public KeyExchange create() {
            return new DHGexSHA1();
        }

        @Override
        public String getName() {
            return "diffie-hellman-group-exchange-sha1";
        }
    }

    public DHGexSHA1() {
        super(new SHA1());
    }
}
