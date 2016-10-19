package net.schmizz.sshj.userauth.keyprovider;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.userauth.password.*;

abstract class BaseFileKeyProvider implements FileKeyProvider {
    protected Resource<?> resource;
    protected PasswordFinder pwdf;
    protected KeyPair kp;

    protected KeyType type;

    @Override
    public void init(Reader location) {
        assert location != null;
        resource = new PrivateKeyReaderResource(location);
    }

    @Override
    public void init(Reader location, PasswordFinder pwdf) {
        init(location);
        this.pwdf = pwdf;
    }

    @Override
    public void init(File location) {
        assert location != null;
        resource = new PrivateKeyFileResource(location.getAbsoluteFile());
    }

    @Override
    public void init(File location, PasswordFinder pwdf) {
        init(location);
        this.pwdf = pwdf;
    }

    @Override
    public void init(String privateKey, String publicKey) {
        assert privateKey != null;
        assert publicKey == null;
        resource = new PrivateKeyStringResource(privateKey);
    }

    @Override
    public void init(String privateKey, String publicKey, PasswordFinder pwdf) {
        init(privateKey, publicKey);
        this.pwdf = pwdf;
    }

    @Override
    public PrivateKey getPrivate()
            throws IOException {
        return kp != null ? kp.getPrivate() : (kp = readKeyPair()).getPrivate();
    }

    @Override
    public PublicKey getPublic()
            throws IOException {
        return kp != null ? kp.getPublic() : (kp = readKeyPair()).getPublic();
    }

    @Override
    public KeyType getType()
            throws IOException {
        return type != null ? type : (type = KeyType.fromKey(getPublic()));
    }


    protected abstract KeyPair readKeyPair() throws IOException;
}
