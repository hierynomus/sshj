/*
 * Copyright 2010 Shikhar Bhushan
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
package net.schmizz.sshj.userauth.method;

import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;

public class PasswordResponseProvider
        implements ChallengeResponseProvider {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final char[] EMPTY_RESPONSE = new char[0];

    private final PasswordFinder pwdf;
    private Resource resource;
    private boolean gaveOnce;

    public PasswordResponseProvider(PasswordFinder pwdf) {
        this.pwdf = pwdf;
    }

    @Override
    public List<String> getSubmethods() {
        return Collections.emptyList();
    }

    @Override
    public void init(Resource resource, String name, String instruction) {
        this.resource = resource;
        log.debug("name=`{}`; instruction=`{}`", name, instruction);
    }

    @Override
    public char[] getResponse(String prompt, boolean echo) {
        if (!gaveOnce && !echo && prompt.toLowerCase().contains("password")) {
            gaveOnce = true;
            log.debug("prompt = `{}`", prompt);
            return pwdf.reqPassword(resource);
        }
        return EMPTY_RESPONSE;
    }

    @Override
    public boolean shouldRetry() {
        return pwdf.shouldRetry(resource);
    }

}