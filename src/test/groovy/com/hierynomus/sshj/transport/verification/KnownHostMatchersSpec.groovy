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
package com.hierynomus.sshj.transport.verification

import spock.lang.Specification
import spock.lang.Unroll

class KnownHostMatchersSpec extends Specification {

    @Unroll
    def "should #yesno match host #host with pattern #pattern"() {
        given:
        def matcher = KnownHostMatchers.createMatcher(pattern)

        expect:
        match == matcher.match(host)

        where:
        pattern       | host          | match
        "aaa.bbb.com" | "aaa.bbb.com" | true
        "aaa.bbb.com" | "aaa.ccc.com" | false
        "*.bbb.com"   | "aaa.bbb.com" | true
        "*.bbb.com"   | "aaa.ccc.com" | false
        "aaa.*.com"   | "aaa.bbb.com" | true
        "aaa.*.com"   | "aaa.ccc.com" | true
        "aaa.bbb.*" | "aaa.bbb.com" | true
        "aaa.bbb.*" | "aaa.ccc.com" | false
        "!*.bbb.com" | "aaa.bbb.com" | false
        "!*.bbb.com" | "aaa.ccc.com" | true
        "aaa.bbb.com,!*.ccc.com" | "xxx.yyy.com" | true
        "aaa.bbb.com,!*.ccc.com" | "aaa.bbb.com" | true
        "aaa.bbb.com,!*.ccc.com" | "aaa.ccc.com" | false
        "aaa.b??.com" | "aaa.bbb.com" | true
        "aaa.b??.com" | "aaa.bcd.com" | true
        "aaa.b??.com" | "aaa.ccd.com" | false
        "aaa.b??.com" | "aaa.bccd.com" | false
        "|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg=" | "192.168.1.61" | true
        "|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg=" | "192.168.2.61" | false
        "[aaa.bbb.com]:2222" | "aaa.bbb.com" | false
        "[aaa.bbb.com]:2222" | "[aaa.bbb.com]:2222" | true
        "[aaa.?bb.com]:2222" | "[aaa.dbb.com]:2222" | true
        "[aaa.?xb.com]:2222" | "[aaa.dbb.com]:2222" | false
        "[*.bbb.com]:2222" | "[aaa.bbb.com]:2222" | true
        yesno = match ? "" : "no"
    }
}
