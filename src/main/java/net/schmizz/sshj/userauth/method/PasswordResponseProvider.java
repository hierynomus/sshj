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
package net.schmizz.sshj.userauth.method;

import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;
import org.slf4j.Logger;

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

public class PasswordResponseProvider
        implements ChallengeResponseProvider {

    public static final Pattern DEFAULT_PROMPT_PATTERN = Pattern.compile(".*[pP]assword:\\s?\\z", Pattern.DOTALL);

    private static final char[] EMPTY_RESPONSE = new char[0];

    private final Pattern promptPattern;
    private final PasswordFinder pwdf;
    private final Logger log;

    private Resource resource;

    public PasswordResponseProvider(PasswordFinder pwdf) {
        this(pwdf, DEFAULT_PROMPT_PATTERN);
    }

    public PasswordResponseProvider(PasswordFinder pwdf, Pattern promptPattern) {
        this(pwdf, promptPattern, LoggerFactory.DEFAULT);
    }

    public PasswordResponseProvider(PasswordFinder pwdf, Pattern promptPattern, LoggerFactory loggerFactory) {
        this.pwdf = pwdf;
        this.promptPattern = promptPattern;
        log = loggerFactory.getLogger(getClass());
    }

    @Override
    public List<String> getSubmethods() {
        return Collections.emptyList();
    }

    @Override
    public void init(Resource resource, String name, String instruction) {
        this.resource = resource;
        log.debug("Challenge - name=`{}`; instruction=`{}`", name, instruction);
    }

    @Override
    public char[] getResponse(String prompt, boolean echo) {
        if (!echo && promptPattern.matcher(prompt).matches()) {
            return pwdf.reqPassword(resource);
        }
        return EMPTY_RESPONSE;
    }

    @Override
    public boolean shouldRetry() {
        return pwdf.shouldRetry(resource);
    }

}
