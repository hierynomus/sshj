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
package net.schmizz.sshj.transport.mac;

import com.hierynomus.sshj.transport.mac.Macs;

/** HMAC-SHA1-96 <code>MAC</code>
 *
 * @deprecated Use {@link Macs#HMACSHA196()}
 */
public class HMACSHA196
        extends BaseMAC {

    /** Named factory for the HMAC-SHA1-96 <code>MAC</code> */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<MAC> {

        @Override
        public MAC create() {
            return new HMACSHA196();
        }

        @Override
        public String getName() {
            return "hmac-sha1-96";
        }
    }

    public HMACSHA196() {
        super("HmacSHA1", 12, 20);
    }
}
