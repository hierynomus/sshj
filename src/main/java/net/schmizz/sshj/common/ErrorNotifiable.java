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
package net.schmizz.sshj.common;

import java.util.Collection;

/** API for classes that are capable of being notified on an error so they can cleanup. */
public interface ErrorNotifiable {

    /** Utility functions. */
    class Util {

        /** Notify all {@code notifiables} of given {@code error}. */
        public static void alertAll(SSHException error, ErrorNotifiable... notifiables) {
            for (ErrorNotifiable notifiable : notifiables)
                notifiable.notifyError(error);
        }

        /** Notify all {@code notifiables} of given {@code error}. */
        public static void alertAll(SSHException error, Collection<? extends ErrorNotifiable> notifiables) {
            for (ErrorNotifiable notifiable : notifiables)
                notifiable.notifyError(error);
        }
    }

    /** Notifies this object of an {@code error}. */
    void notifyError(SSHException error);

}
