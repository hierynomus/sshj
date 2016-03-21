package net.schmizz.sshj.userauth.password;

/**
 * Callback that can be implemented to allow an application to provide an updated password for the 'auth-password'
 * authentication method.
 */
public interface PasswordUpdateProvider {

    /**
     * Called with the prompt received from the SSH server. This should return the updated password for the user that is
     * currently authenticating.
     *
     * @param resource The resource for which the updated password is being requested.
     * @param prompt The password update prompt received from the SSH Server.
     * @return The new password for the resource.
     */
    char[] provideNewPassword(Resource<?> resource, String prompt);

    /**
     * If password turns out to be incorrect, indicates whether another call to {@link #provideNewPassword(Resource, String)} should be
     * made.
     * <p/>
     * This method is geared at interactive implementations, and stub implementations may simply return {@code false}.
     *
     * @param resource the resource for which the updated password is being requested
     *
     * @return whether to retry requesting the updated password for a particular resource
     */
    boolean shouldRetry(Resource<?> resource);
}
