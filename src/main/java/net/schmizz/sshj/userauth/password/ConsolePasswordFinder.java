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
import java.util.IllegalFormatException;

/** A PasswordFinder that reads a password from a console */
public class ConsolePasswordFinder implements PasswordFinder {

    public static final String DEFAULT_FORMAT = "Enter passphrase for %s:";

    private final Console console;
    private final String promptFormat;
    private final int maxTries;

    private int numTries;

    public ConsolePasswordFinder() {
        this(System.console());
    }

    public ConsolePasswordFinder(Console console) {
        this(console, DEFAULT_FORMAT, 3);
    }

    public ConsolePasswordFinder(Console console, String promptFormat, int maxTries) {
        checkFormatString(promptFormat);
        this.console = console;
        this.promptFormat = promptFormat;
        this.maxTries = maxTries;
        this.numTries = 0;
    }

    @Override
    public char[] reqPassword(Resource<?> resource) {
        numTries++;
        if (console == null) {
            // the request cannot be serviced
            return null;
        }
        return console.readPassword(promptFormat, resource.toString());
    }

    @Override
    public boolean shouldRetry(Resource<?> resource) {
        return numTries < maxTries;
    }

    private static void checkFormatString(String promptFormat) {
        try {
            String.format(promptFormat, "");
        } catch (IllegalFormatException e) {
            throw new IllegalArgumentException("promptFormat must have no more than one %s and no other markers", e);
        }
    }

}
