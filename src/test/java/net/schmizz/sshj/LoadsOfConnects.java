/*
 * Copyright 2010, 2011 sshj contributors
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
package net.schmizz.sshj;

import net.schmizz.sshj.util.BasicFixture;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/* Kinda basic right now */
public class LoadsOfConnects {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final BasicFixture fixture = new BasicFixture();

    @Test
    public void loadsOfConnects()
            throws IOException, InterruptedException {
        for (int i = 0; i < 1000; i++) {
            System.out.println("Try " + i);
            fixture.init(false);
            fixture.done();
        }
    }

}