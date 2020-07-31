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
package com.hierynomus.sshj.common

import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile
import spock.lang.Specification
import spock.lang.Unroll

class KeyTypeSpec extends Specification {

    @Unroll
    def "should determine correct keytype for #type key"() {
        given:
        OpenSSHKeyFile kf = new OpenSSHKeyFile()
        kf.init(privKey, pubKey)

        expect:
        KeyType.fromKey(kf.getPublic()) == type
        KeyType.fromKey(kf.getPrivate()) == privateType

        where:
        privKey << [
                """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGhcvG8anyHew/xZJfozh5XIc1kmZZs6o2f0l3KFs4jgoAoGCCqGSM49
AwEHoUQDQgAEDUA1JYVD7URSoOGdwPxjea+ETD6IABMD9CWfk3NVTNkdu/Ksn7uX
cLTQhx4N16z1IgW2bRbSbsmM++UKXmeWyg==
-----END EC PRIVATE KEY-----""",

                // ssh-keygen -f ca_key -N '' -t rsa -b 1024 \
                // && ssh-keygen -f id_rsa_test -N '' -t rsa -b 1024 -m pem \
                // && cat id_rsa_test
                """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDNBlUYU5KebH8PBf5i58zFI7xW2CLwUrzKA3949+0wnA9JzrX1
XWiVJG3gNgQEgUZIIrPfPAMk9x6hVdBKL9gi3tRUfGTQfQZ7JN9rMFmlbLmEFHd4
RY86OHe2h7SO+xfYBieR7aL0DsbwcBZIWm0xlotHzR6d3QodMLYZh0jleQIDAQAB
AoGAdzHIRRVJN0tSbxSH+U5T8QS+mSqc3WTslvGDqXtR7SG9jaZciOKeS57bNi+R
FGFnz8ZFFnJYTaRRrXArYQYBu/Fp5EtMJQ52G04gGI5mov+4vACaJ3J98wieBMZh
miQXZUXjmCIkE+3/SxIIE1Cf2J8Epa012FZ5vcu+kfjOZZECQQDwTm2Hdp8PTpTm
BX802Z7zO/ZfW+oGK4LIqvcUqf/2NnA3zpgjAwl9FtxpSzzq4lvcNMTANk3ZkJIg
VZsn5Ar9AkEA2moMF2AvWuW7LN5aDKpyPqJJv9fxM1HOkrYWu6aYyl/r5/RaIwSp
Bl/5W1Elg5xgYbnms1wtgLIpipfAofoDLQJAG0XrbGpsFwKmJ40MKOViAt0VUzFN
WDHr//ZXYIMCx+DZz5uk7KRVmVrU3SZq3YWfQ1jB08bWAxFDZGQS3e4lyQJBANki
bkza6ZkjJFax4rIOzS7pZgob4wWTAZum/KinMeSXQc7ChM2ld2gIB705yeKylrrw
9qI/NFlqRZQr02z0QS0CQQDVnk224ebhcFlUG6AFcQW/b3O9yqKh6Qj7q9AK5CbV
8T8wEvB6yg929UbNSzqtKFHD2+oq/VQF7sym8BTCA9jp
-----END RSA PRIVATE KEY-----""",

                // ssh-keygen -f ca_key -N '' -t rsa -b 1024 \
                // && ssh-keygen -f id_dsa_test -N '' -t dsa -b 1024 -m pem \
                // && cat id_dsa_test
                """-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDCY3/O8Locj4ByO/tFiGi83rQNFlCeD44ZBiZgCMCh687H49OC
r1G8Z6Ga55uLp87DXhdEjq8HXgMhDXQakqF5huOyTkPibdsOlv86l3sw8NBBGGMF
OE4t6Qj2pVA2YrvUKY7UiyZpOdLVzrXAcouE/32259vDIbX6Y84F+TzZKwIVAOR3
zWOxnbR8wR9xKdcMczNlxOtBAoGAVBDn7jKB76oTzcmCnDyoBNISNNiknuhyM0xp
hfVMGMgUw72WLWE9k9LYBZMRWBLAeI3C5PuV0cJuSXOz1maY9B+NHr9z7AmMfPF0
eK3Fr7IHyr1DcZNZ3yE7UX4UPB/9blgxj/m1/Kvgvl/l9F+wDIH/uAJ+Awuv5a8w
jVAaZPcCgYB/vvvduepAMBYSHB3/J7a9GeEAhIlu69fGhiwUmrD1hTWKa4skVKDT
PcJ/j1urFglMdh/hKB3DdjT5Fs+95VJYvBBuOwhZ/XwQCQcFLlSXi/CvbaV63f8d
f26VSnEypH3G3cmPYfpVcXL63bCb0E4sNJwENM4tQGZa5YGz3CxMdgIVAJUv4z9+
2AE1NF07cGZ4Zs9euh9y
-----END DSA PRIVATE KEY-----""",
        ]
        pubKey << [
                """ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA1ANSWFQ+1EUqDhncD8Y3mvhEw+iAATA/Qln5NzVUzZHbvyrJ+7l3C00IceDdes9SIFtm0W0m7JjPvlCl5nlso= SSH Key""",

                // ssh-keygen -s ca_key -I sshj_test -n user -V +240m id_rsa_test.pub \
                // && cat id_rsa_test-cert.pub
                """ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgKXsDoXKTlSaN3N/z6OwYQwCWMAf6N5CidrRJMe+IUOwAAAADAQABAAAAgQDNBlUYU5KebH8PBf5i58zFI7xW2CLwUrzKA3949+0wnA9JzrX1XWiVJG3gNgQEgUZIIrPfPAMk9x6hVdBKL9gi3tRUfGTQfQZ7JN9rMFmlbLmEFHd4RY86OHe2h7SO+xfYBieR7aL0DsbwcBZIWm0xlotHzR6d3QodMLYZh0jleQAAAAAAAAAAAAAAAQAAAAlzc2hqX3Rlc3QAAAAIAAAABHVzZXIAAAAAXuczLAAAAABe52vUAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAN4tykUwkwobduBrqTJW7HNJP1Z6bAhzNNA1P2KY+0aO0iBhISHcaWS0vKsgQ4BYbbVfTkrc0rEuRnajl9PhhEyZgJs8oR7sGndxAlDY6UJH4wSL3j7A+2bogoSbpOfWZiPp/tJohPBvmsN6Uv89Axs0L7V338yH3UE4bX6eIQDZVjKjL7evOYz7sOdV7pUYvgzErqzVxxmF7t/yd61rNOOLm0PY4O1HpW2ZYGGtG8YIC8asFYY2EouLy8OsP2z7U8DLFokTuMsTA6ADN5tYbzBqxUCMsuUPqdGz4xnlTja7jm4FjBFa91KmpQSOWhveaQeb91dwMeomyplYH8W6tkDuXR7acncxYAjB955ws/T9qWrACWFryskUGI1oupM5QVXveO793oWoSqtDi6BOw763Z+7oekmScOOSpeRgsNvSPN+RMyDDuT0Sf4Tc/aLABow6t5UfULAwv9xqLg9QH6CS9ZSkIWNiEOkhCa1uH2srSF6e9m2XN0f5EawZ81EYBQAAAZQAAAAMcnNhLXNoYTItNTEyAAABgFrJp0zHjElwO+PV/hd5zXydySLLKI6A/UzCnCcceSY46oO94Uzn3Bc8UKdxMctlMOG1LGeiuYE/CMMGwnuo1TLWrfY1anVigPx0CrHzjE7ZT4qhCJsVmuwpU3qcZOrom+bDbco2N30/K81rrU5KlmVG6zGHNOpwRr2zRIusXGQ3/e+dOzsMh1cmO/XntGmxWXYPIHs4TUXE1d5C2hZFN1jkBkvlG6n6ZMq7Z+6V5oVc2bqETJv6zxypt1II7l5ObZJP26x75yb4VEbycHLENYSgSVBoN7pyc7QqRYbTnfdxJBKyjDmjOXAMlAzFch5BVHazw1PNS+BkKLZaDb/dlTfeKjDqIywb97zT4XJ70HUTZB3P/q6OwiTtrKOW9no5C9Wka2EkOliNwvsJyxYxNmS8SEzT/Ezk7vhxzS8C17+uBX55o0nJ1bjPw0E02mAoIu5o0sXm/J+3dW+s1TG1XzXdksUthG8EozQfr5M0MuOeONkwebtAo/JzSF73rlGBlA== sshj@example.com""",

                // ssh-keygen -s ca_key -I sshj_test -n user -V +240m id_dsa_test.pub \
                // && cat id_dsa_test-cert.pub
                """ssh-dss-cert-v01@openssh.com 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 sshj@example.com""",
        ]

        type << [
                KeyType.ECDSA256,
                KeyType.RSA_CERT,
                KeyType.DSA_CERT,
        ]

        privateType << [
                KeyType.ECDSA256,
                KeyType.RSA,
                KeyType.DSA,
        ]
    }
}