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
package com.hierynomus.sshj.transport.kex;

import net.schmizz.sshj.transport.kex.KeyExchange;

/**
 * Stub kex algorithm factory that indicates support for SSH2_MSG_EXT_INFO.
 * Some servers will not send `rsa-sha2-*` signatures if the client doesn't indicate support.
 *
 * Note: Since the server sends `ext-info-s` to indicate support, this fake kex algorithm is never negotiated.
 */
public class ExtInfoClientFactory implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {
    @Override
    public String getName() {
        return "ext-info-c";
    }

    @Override
    public KeyExchange create() {
        return null;
    }
}
