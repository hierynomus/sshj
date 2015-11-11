package com.hierynomus.sshj.transport.cipher;

import net.schmizz.sshj.transport.cipher.BaseCipher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

public class StreamCipher extends BaseCipher {

    public StreamCipher(int bsize, String algorithm, String transformation) {
        super(0, bsize, algorithm, transformation);
    }

    @Override
    protected void initCipher(javax.crypto.Cipher cipher, Mode mode, byte[] key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(getMode(mode), getKeySpec(key), new SecureRandom());
    }
}
