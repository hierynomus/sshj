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
package net.schmizz.sshj.sftp;

import net.schmizz.concurrent.Promise;

import java.io.IOException;

public interface Requester {

    PathHelper getPathHelper();

    Request newRequest(PacketType type);

    Response doRequest(Request req)
            throws IOException;

    Promise<Response, SFTPException> request(Request request)
            throws IOException;

    void retrieve(Promise<Response, SFTPException> response)
            throws IOException;

}
