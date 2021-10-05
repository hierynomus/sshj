package net.schmizz.sshj.util;

import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;

public class UnitTestPasswordFinder implements PasswordFinder {

    private final char[] password;

    public UnitTestPasswordFinder(String password) {
        this.password = password.toCharArray();
    }

    public UnitTestPasswordFinder(char[] password) {
        this.password = password;
    }

    @Override
    public char[] reqPassword(Resource<?> resource) {
        return password;
    }

    @Override
    public boolean shouldRetry(Resource<?> resource) {
        return false;
    }
}
