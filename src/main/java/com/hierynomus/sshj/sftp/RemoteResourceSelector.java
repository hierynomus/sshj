package com.hierynomus.sshj.sftp;

import net.schmizz.sshj.sftp.RemoteResourceInfo;

public interface RemoteResourceSelector {

    enum Result {
        /**
         * Accept the remote resource and add it to the result.
         */
        ACCEPT,

        /**
         * Do not add the remote resource to the result and continue with the next.
         */
        CONTINUE,

        /**
         * Do not add the remote resource to the result and stop further execution.
         */
        BREAK;
    }

    /**
     * Decide whether the remote resource should be included in the result and whether execution should continue.
     */
    Result select(RemoteResourceInfo resource);
}
