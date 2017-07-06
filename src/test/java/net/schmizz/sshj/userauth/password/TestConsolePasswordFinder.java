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
package net.schmizz.sshj.userauth.password;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class TestConsolePasswordFinder {

    /*
     * Note that Mockito 1.9 cannot mock Console because it is a final class,
     * so there are no other tests.
     */

    @Test
    public void testReqPasswordNullConsole() {
        char[] password = new ConsolePasswordFinder(null)
            .reqPassword(Mockito.mock(Resource.class));
        Assert.assertNull("Password should be null with null console", password);
    }

}
