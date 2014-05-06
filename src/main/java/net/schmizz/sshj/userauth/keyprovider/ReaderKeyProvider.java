package net.schmizz.sshj.userauth.keyprovider;

import java.io.Reader;

import net.schmizz.sshj.userauth.password.PasswordFinder;

/**
 * @version $Id:$
 */
public interface ReaderKeyProvider extends KeyProvider {

    void init(Reader location);

    void init(Reader location, PasswordFinder pwdf);
}
