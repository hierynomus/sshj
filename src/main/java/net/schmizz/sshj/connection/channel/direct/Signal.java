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

package net.schmizz.sshj.connection.channel.direct;

/** Various signals that may be sent or received. The signals are from POSIX and simply miss the {@code "SIG_"} prefix. */
public enum Signal {

    ABRT,
    ALRM,
    FPE,
    HUP,
    ILL,
    INT,
    KILL,
    PIPE,
    QUIT,
    SEGV,
    TERM,
    USR1,
    USR2,
    UNKNOWN;

    /**
     * Create from the string representation used when the signal is received as part of an SSH packet.
     *
     * @param name name of the signal as received
     *
     * @return the enum constant inferred
     */
    public static Signal fromString(String name) {
        for (Signal sig : Signal.values())
            if (sig.toString().equals(name))
                return sig;
        return UNKNOWN;
    }

}