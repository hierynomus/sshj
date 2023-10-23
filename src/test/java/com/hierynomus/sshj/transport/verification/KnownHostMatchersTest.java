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
package com.hierynomus.sshj.transport.verification;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class KnownHostMatchersTest {
    @MethodSource("com.hierynomus.sshj.transport.verification.KnownHostMatchersTest#patterns")
    @ParameterizedTest
    public void shouldMatchHostnameToPattern(String pattern, String hostname, boolean match) throws Exception {
        KnownHostMatchers.HostMatcher matcher = KnownHostMatchers.createMatcher(pattern);
        assertEquals(match, matcher.match(hostname));
    }

    public static Stream<Arguments> patterns() {
        return Stream.of(
            Arguments.of("aaa.bbb.com", "aaa.bbb.com", true),
            Arguments.of("aaa.bbb.com", "aaa.ccc.com", false),
            Arguments.of("*.bbb.com"  , "aaa.bbb.com", true),
            Arguments.of("*.bbb.com"  , "aaa.ccc.com", false),
            Arguments.of("aaa.*.com"  , "aaa.bbb.com", true),
            Arguments.of("aaa.*.com"  , "aaa.ccc.com", true),
            Arguments.of("aaa.bbb.*", "aaa.bbb.com", true),
            Arguments.of("aaa.bbb.*", "aaa.ccc.com", false),
            Arguments.of("!*.bbb.com", "aaa.bbb.com", false),
            Arguments.of("!*.bbb.com", "aaa.ccc.com", true),
            Arguments.of("aaa.bbb.com,!*.ccc.com", "xxx.yyy.com", true),
            Arguments.of("aaa.bbb.com,!*.ccc.com", "aaa.bbb.com", true),
            Arguments.of("aaa.bbb.com,!*.ccc.com", "aaa.ccc.com", false),
            Arguments.of("aaa.b??.com", "aaa.bbb.com", true),
            Arguments.of("aaa.b??.com", "aaa.bcd.com", true),
            Arguments.of("aaa.b??.com", "aaa.ccd.com", false),
            Arguments.of("aaa.b??.com", "aaa.bccd.com", false),
            Arguments.of("|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg=", "192.168.1.61", true),
            Arguments.of("|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg=", "192.168.2.61", false),
            Arguments.of("[aaa.bbb.com]:2222", "aaa.bbb.com", false),
            Arguments.of("[aaa.bbb.com]:2222", "[aaa.bbb.com]:2222", true),
            Arguments.of("[aaa.?bb.com]:2222", "[aaa.dbb.com]:2222", true),
            Arguments.of("[aaa.?xb.com]:2222", "[aaa.dbb.com]:2222", false),
            Arguments.of("[*.bbb.com]:2222", "[aaa.bbb.com]:2222", true)
        );
    }
}
