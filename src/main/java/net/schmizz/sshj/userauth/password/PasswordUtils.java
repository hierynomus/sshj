/*
 * Copyright 2010-2012 sshj contributors
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

import java.util.Arrays;

/** Static utility method and factories */
public class PasswordUtils {

    /**
     * Blank out a character array
     *
     * @param pwd the character array
     */
    public static void blankOut(char[] pwd) {
        if (pwd != null)
            Arrays.fill(pwd, ' ');
    }

    /**
     * @param password the password as a char[]
     *
     * @return the constructed {@link PasswordFinder}
     */
    public static PasswordFinder createOneOff(final char[] password) {
        if (password == null)
            return null;
        else
            return new PasswordFinder() {
                @Override
                public char[] reqPassword(Resource<?> resource) {
                    char[] cloned = password.clone();
                    blankOut(password);
                    return cloned;
                }

                @Override
                public boolean shouldRetry(Resource<?> resource) {
                    return false;
                }
            };
    }

}
