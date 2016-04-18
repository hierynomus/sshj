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
package net.schmizz.sshj.userauth;

import net.schmizz.sshj.Service;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.method.AuthMethod;

/** User authentication API. See RFC 4252. */
public interface UserAuth {

    /**
     * Attempt to authenticate {@code username} using each of {@code methods} in order. {@code nextService} is the
     * {@link Service} that will be enabled on successful authentication.
     * <p/>
     * Authentication fails if there are no method available, i.e. if all the method failed or there were method
     * available but could not be attempted because the server did not allow them.
     * <p/>
     * Further attempts may also be made by catching {@code UserAuthException} and retrying with this method.
     *
     * @param username    the user to authenticate
     * @param nextService the service to set on successful authentication
     * @param methods     the {@link AuthMethod}'s to try
     *
     * @return whether authentication was successful
     *
     * @throws UserAuthException  in case of authentication failure
     * @throws TransportException if there was a transport-layer error
     */
    boolean authenticate(String username, Service nextService, AuthMethod methods, int timeoutMs)
            throws UserAuthException, TransportException;

    /**
     * Returns the authentication banner (if any). In some cases this is available even before the first authentication
     * request has been made.
     *
     * @return the banner, or an empty string if none was received
     */
    String getBanner();

    /**
     * @return whether authentication was partially successful. Some server's may be configured to require multiple
     *         authentications; and this value will be {@code true} if at least one of the method supplied succeeded.
     */
    boolean hadPartialSuccess();

    /** The available authentication methods. This is only defined once an unsuccessful authentication has taken place. */
    Iterable<String> getAllowedMethods();

}
