package com.hierynomus.sshj.transport.mac;

import net.schmizz.sshj.transport.mac.BaseMAC;

public class Macs {
    public static Factory HMACMD5() {
        return new Factory("hmac-md5", "HmacMD5", 16, 16);
    }
    public static Factory HMACMD596() {
        return new Factory("hmac-md5-96", "HmacMD5", 12, 16);
    }
    public static Factory HMACRIPEMD160() {
        return new Factory("hmac-ripemd160", "HMACRIPEMD160", 20, 20);
    }
    public static Factory HMACRIPEMD16096() {
        return new Factory("hmac-ripemd160-96", "HMACRIPEMD160", 12, 20);
    }
    public static Factory HMACRIPEMD160OpenSsh() {
        return new Factory("hmac-ripemd160@openssh.com", "HMACRIPEMD160", 20, 20);
    }
    public static Factory HMACSHA1() {
        return new Factory("hmac-sha1", "HmacSHA1", 20, 20);
    }
    public static Factory HMACSHA196() {
        return new Factory("hmac-sha1-96", "HmacSHA1", 12, 20);
    }
    public static Factory HMACSHA2256() {
        return new Factory("hmac-sha2-256", "HmacSHA256", 32, 32);
    }
    public static Factory HMACSHA2512() {
        return new Factory("hmac-sha2-512", "HmacSHA512", 64, 64);
    }

    private static class Factory implements net.schmizz.sshj.common.Factory.Named<BaseMAC> {

        private String name;
        private String algorithm;
        private int bSize;
        private int defBSize;

        public Factory(String name, String algorithm, int bSize, int defBSize) {
            this.name = name;
            this.algorithm = algorithm;
            this.bSize = bSize;
            this.defBSize = defBSize;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public BaseMAC create() {
            return new BaseMAC(algorithm, bSize, defBSize);
        }
    }
}
