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

/** Services requests for plaintext passwords. */
public interface PasswordFinder {

    /**
     * Request password for specified resource.
     * <p/>
     * This method may return {@code null} when the request cannot be serviced, e.g. when the user cancels a password
     * prompt.
     *
     * @param resource the resource for which password is being requested
     *
     * @return the password or {@code null}
     */
    char[] reqPassword(Resource<?> resource);

    /**
     * If password turns out to be incorrect, indicates whether another call to {@link #reqPassword(Resource)} should be
     * made.
     * <p/>
     * This method is geared at interactive implementations, and stub implementations may simply return {@code false}.
     *
     * @param resource the resource for which password is being requested
     *
     * @return whether to retry requesting password for a particular resource
     */
    boolean shouldRetry(Resource<?> resource);

}
