package net.schmizz.sshj.transport.cipher;

import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

public class BlockCipher extends BaseCipher {
    public BlockCipher(int ivsize, int bsize, String algorithm, String transformation) {
        super(ivsize, bsize, algorithm, transformation);
    }

    protected void initCipher(javax.crypto.Cipher cipher, Mode mode, byte[] key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(getMode(mode),
                getKeySpec(key), new IvParameterSpec(iv));
    }

}
