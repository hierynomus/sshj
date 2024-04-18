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
package com.hierynomus.sshj.sftp;

import net.schmizz.sshj.sftp.RemoteResourceInfo;

public interface RemoteResourceSelector {
    public static RemoteResourceSelector ALL = new RemoteResourceSelector() {
        @Override
        public Result select(RemoteResourceInfo resource) {
            return Result.ACCEPT;
        }
    };

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
