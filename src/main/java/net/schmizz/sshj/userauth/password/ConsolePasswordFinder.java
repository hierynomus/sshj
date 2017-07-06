/*
 * Copyright (C)2009 - SSHJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.schmizz.sshj.userauth.password;

import java.io.Console;

/** A PasswordFinder that reads a password from a console */
public class ConsolePasswordFinder implements PasswordFinder {

    private final Console console;

    /**
     * Initializes with the System Console, which will be null if not run from an interactive shell.
     */
    public ConsolePasswordFinder() {
        this(System.console());
    }

    /**
     * @param console the console to read the password from.  May be null.
     */
    public ConsolePasswordFinder(Console console) {
        this.console = console;
    }

    @Override
    public char[] reqPassword(Resource<?> resource) {
        if (console == null) {
            // the request cannot be serviced
            return null;
        }
        return console.readPassword("Enter passphrase for %s:", resource.toString());
    }

    @Override
    public boolean shouldRetry(Resource<?> resource) {
        return true;
    }
}
