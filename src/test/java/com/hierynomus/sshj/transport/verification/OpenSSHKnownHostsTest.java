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

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts;
import net.schmizz.sshj.util.KeyUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PublicKey;
import java.util.Base64;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

public class OpenSSHKnownHostsTest {
    @TempDir
    public File tempDir;

    @BeforeAll
    public static void setup() {
        SecurityUtils.registerSecurityProvider("org.bouncycastle.jce.provider.BouncyCastleProvider");
    }

    @Test
    public void shouldParseAndVerifyHashedHostEntry() throws Exception {
        File knownHosts = knownHosts(
                "|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6P9Hlwdahh250jGZYKg2snRq2j2lFJVdKSHyxqbJiVy9VX9gTkN3K2MD48qyrYLYOyGs3vTttyUk+cK++JMzURWsrP4piby7LpeOT+3Iq8CQNj4gXZdcH9w15Vuk2qS11at6IsQPVHpKD9HGg9//EFUccI/4w06k4XXLm/IxOGUwj6I2AeWmEOL3aDi+fe07TTosSdLUD6INtR0cyKsg0zC7Da24ixoShT8Oy3x2MpR7CY3PQ1pUVmvPkr79VeA+4qV9F1JM09WdboAMZgWQZ+XrbtuBlGsyhpUHSCQOya+kOJ+bYryS+U7A+6nmTW3C9FX4FgFqTF89UHOC7V0zZQ==");
        PublicKey k = KeyUtil.newRSAPublicKey(
                "e8ff4797075a861db9d2319960a836b2746ada3da514955d2921f2c6a6c9895cbd557f604e43772b6303e3cab2ad82d83b21acdef4edb72524f9c2bef893335115acacfe2989bcbb2e978e4fedc8abc090363e205d975c1fdc35e55ba4daa4b5d5ab7a22c40f547a4a0fd1c683dfff10551c708ff8c34ea4e175cb9bf2313865308fa23601e5a610e2f76838be7ded3b4d3a2c49d2d40fa20db51d1cc8ab20d330bb0dadb88b1a12853f0ecb7c7632947b098dcf435a54566bcf92befd55e03ee2a57d17524cd3d59d6e800c66059067e5eb6edb81946b3286950748240ec9afa4389f9b62bc92f94ec0fba9e64d6dc2f455f816016a4c5f3d507382ed5d3365",
                "23");

        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);
        assertTrue(ohk.verify("192.168.1.61", 22, k));
        assertFalse(ohk.verify("192.168.1.2", 22, k));
        ohk.write();
        for (OpenSSHKnownHosts.KnownHostEntry entry : ohk.entries()) {
            assertEquals("|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6P9Hlwdahh250jGZYKg2snRq2j2lFJVdKSHyxqbJiVy9VX9gTkN3K2MD48qyrYLYOyGs3vTttyUk+cK++JMzURWsrP4piby7LpeOT+3Iq8CQNj4gXZdcH9w15Vuk2qS11at6IsQPVHpKD9HGg9//EFUccI/4w06k4XXLm/IxOGUwj6I2AeWmEOL3aDi+fe07TTosSdLUD6INtR0cyKsg0zC7Da24ixoShT8Oy3x2MpR7CY3PQ1pUVmvPkr79VeA+4qV9F1JM09WdboAMZgWQZ+XrbtuBlGsyhpUHSCQOya+kOJ+bYryS+U7A+6nmTW3C9FX4FgFqTF89UHOC7V0zZQ==",
                    entry.getLine());
        }
    }

    @Test
    public void shouldParseAndVerifyV1HostEntry() throws Exception {
        File knownHosts = knownHosts(
                "test.com,1.1.1.1 2048 35 22017496617994656680820635966392838863613340434802393112245951008866692373218840197754553998457793202561151141246686162285550121243768846314646395880632789308110750881198697743542374668273149584280424505890648953477691795864456749782348425425954366277600319096366690719901119774784695056100331902394094537054256611668966698242432417382422091372756244612839068092471592121759862971414741954991375710930168229171638843329213652899594987626853020377726482288618521941129157643483558764875338089684351824791983007780922947554898825663693324944982594850256042689880090306493029526546183035567296830604572253312294059766327");
        PublicKey k = KeyUtil.newRSAPublicKey(
                "ae6983ed63a33afc69fe0b88b4ba14393120a0b66e1460916a8390ff109139cd14f4e1701ab5c5feeb479441fe2091d04c0ba7d3fa1756b80ed103657ab53b5d7daa38af22f59f9cbfc16892d4ef1f8fd3ae49663c295be1f568a160d54328fbc2c0598f48d32296b1b9942336234952c440cda1bfac904e3391db98e52f9b1de229adc18fc34a9a569717aa9a5b1145e73b8a8394354028d02054ca760243fb8fc1575490607dd098e698e02b5d8bdf22d55ec958245222ef4c65b8836b9f13674a2d2895a587bfd4423b4eeb6d3ef98451640e3d63d2fc6a761ffd34446abab028494caf36d67ffd65298d69f19f2d90bae4c207b671db563a08f1bb9bf237",
                "23");

        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);
        assertTrue(ohk.verify("test.com", 22, k));
    }

    @Test
    public void shouldTestAllHostEntriesForKey() throws Exception {
        File knownHosts = knownHosts(
                "host1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCiYp2IDgzDFhl8T4TRLIhEljvEixz1YN0XWh4dYh0REGK9T4QKiyb28EztPMdcOtz1uyX5rUGYXX9hj99S4SiU=\n"
                        +
                        "host1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLTjA7hduYGmvV9smEEsIdGLdghSPD7kL8QarIIOkeXmBh+LTtT/T1K+Ot/rmXCZsP8hoUXxbvN+Tks440Ci0ck=\n");
        PublicKey k = new Buffer.PlainBuffer(Base64.getDecoder().decode(
                "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLTjA7hduYGmvV9smEEsIdGLdghSPD7kL8QarIIOkeXmBh+LTtT/T1K+Ot/rmXCZsP8hoUXxbvN+Tks440Ci0ck="))
                .readPublicKey();

        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);
        assertTrue(ohk.verify("host1", 22, k));
    }

    @Test
    public void shouldNotFailOnBadBase64Entry() throws Exception {
        File knownHosts = knownHosts(
                "host1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTIDgzDFhl8T4TRLIhEljvEixz1YN0XWh4dYh0REGK9T4QKiyb28EztPMdcOtz1uyX5rUGYXX9hj99S4SiU=\n"
                        +
                        "host1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLTjA7hduYGmvV9smEEsIdGLdghSPD7kL8QarIIOkeXmBh+LTtT/T1K+Ot/rmXCZsP8hoUXxbvN+Tks440Ci0ck=\n");
        PublicKey k = new Buffer.PlainBuffer(Base64.getDecoder().decode(
                "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLTjA7hduYGmvV9smEEsIdGLdghSPD7kL8QarIIOkeXmBh+LTtT/T1K+Ot/rmXCZsP8hoUXxbvN+Tks440Ci0ck="))
                .readPublicKey();
        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);

        assertTrue(ohk.verify("host1", 22, k));
    }

    @Test
    public void shouldNotFailOnMalformedBase64String() throws IOException {
        File knownHosts = knownHosts(
                "1.1.1.1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA/CkqWXSlbdo7jPshvIWT/m3FAdpSIKUx/uTmz87ObpBxXsfF8aMSiwGMKHjqviTV4cG6F7vFf28ll+9CbGsbs=192\n"
        );
        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);
        assertEquals(1, ohk.entries().size());
        assertThat(ohk.entries().get(0)).isInstanceOf(OpenSSHKnownHosts.BadHostEntry.class);
    }

    @Test
    public void shouldNotFailOnMalformeSaltBase64String() throws IOException {
        // A record with broken base64 inside the salt part of the hash.
        // No matter how it could be generated, such broken strings must not cause unexpected errors.
        String hostName = "example.com";
        File knownHosts = knownHosts(
                "|1|2gujgGa6gJnK7wGPCX8zuGttvCMXX|Oqkbjtxd9RFxKQv6y3l3GIxLNiU= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGVVnyoAD5/uWiiuTSM3RuW8dEWRrqOXYobAMKHhAA6kuOBoPK+LoAYyUcN26bdMiCxg+VOaLHxPNWv5SlhbMWw=\n"
        );
        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);
        assertEquals(1, ohk.entries().size());

        // Some random valid public key. It doesn't matter for the test if it matches the broken host key record or not.
        PublicKey k = new Buffer.PlainBuffer(Base64.getDecoder().decode(
                "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLTjA7hduYGmvV9smEEsIdGLdghSPD7kL8QarIIOkeXmBh+LTtT/T1K+Ot/rmXCZsP8hoUXxbvN+Tks440Ci0ck="))
                .readPublicKey();
        assertFalse(ohk.verify(hostName, 22, k));
    }

    @Test
    public void shouldMarkBadLineAndNotFail() throws Exception {
        File knownHosts = knownHosts(
                "M36Lo+Ik5ukNugvvoNFlpnyiHMmtKxt3FpyEfYuryXjNqMNWHn/ARVnpUIl5jRLTB7WBzyLYMG7X5nuoFL9zYqKGtHxChbDunxMVbspw5WXI9VN+qxcLwmITmpEvI9ApyS/Ox2ZyN7zw==\n");
        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);
        assertEquals(1, ohk.entries().size());
        assertInstanceOf(OpenSSHKnownHosts.BadHostEntry.class, ohk.entries().get(0));
    }

    @Test
    public void shouldAddCommentForSpecificLines() throws Exception {
        File knownHosts = knownHosts("#comment\n\n");
        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);
        assertEquals(2, ohk.entries().size());
        assertInstanceOf(OpenSSHKnownHosts.CommentEntry.class, ohk.entries().get(0));
        assertInstanceOf(OpenSSHKnownHosts.CommentEntry.class, ohk.entries().get(1));
    }

    @Test
    public void shouldNotVerifyRevokedEntries() throws Exception {
        File knownHosts = knownHosts("host1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIRsJi92NJJTQwXHZiRiARoEy4n1jYsNTQePHFTSl7tG\n" +
                "@revoked revoked-host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIRsJi92NJJTQwXHZiRiARoEy4n1jYsNTQePHFTSl7tG\n");

        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);
        PublicKey k = new Buffer.PlainBuffer(Base64.getDecoder().decode(
                "AAAAC3NzaC1lZDI1NTE5AAAAIIRsJi92NJJTQwXHZiRiARoEy4n1jYsNTQePHFTSl7tG"))
                .readPublicKey();

        assertTrue(ohk.verify("host1", 22, k));
        assertFalse(ohk.verify("revoked-host", 22, k));
    }

    @Test
    public void shouldForgiveRedundantSpacesLikeOpenSSH() throws Exception {
        File knownHosts = knownHosts(
                "host1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIRsJi92NJJTQwXHZiRiARoEy4n1jYsNTQePHFTSl7tG\n" +
                "\n" +
                " host2   ssh-ed25519  AAAAC3NzaC1lZDI1NTE5AAAAIIRsJi92NJJTQwXHZiRiARoEy4n1jYsNTQePHFTSl7tG   ,./gargage\\.,\n" +
                "\t\t\t\t\t\t\n" +
                        "\t  host3\tssh-ed25519\t \tAAAAC3NzaC1lZDI1NTE5AAAAIIRsJi92NJJTQwXHZiRiARoEy4n1jYsNTQePHFTSl7tG\t\n");
        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);

        PublicKey pk = new Buffer.PlainBuffer(
                Base64.getDecoder().decode("AAAAC3NzaC1lZDI1NTE5AAAAIIRsJi92NJJTQwXHZiRiARoEy4n1jYsNTQePHFTSl7tG"))
                .readPublicKey();

        assertTrue(ohk.verify("host1", 22, pk));
        assertTrue(ohk.verify("host2", 22, pk));
        assertTrue(ohk.verify("host3", 22, pk));
    }

    @Test
    public void shouldNotThrowErrorsWhileParsingCorruptRecords() throws Exception {
        File knownHosts = knownHosts(
                "\n" // empty line
                        + "    \n" // blank line
                        + "bad-host1\n" // absent key type and key contents
                        + "bad-host2 ssh-ed25519\n" // absent key contents
                        + "  bad-host3 ssh-ed25519\n" // absent key contents, with leading spaces
                        + "@revoked  bad-host5 ssh-ed25519\n" // absent key contents, with marker
                        + "good-host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIRsJi92NJJTQwXHZiRiARoEy4n1jYsNTQePHFTSl7tG" // the only good host at the end
        );
        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);

        assertTrue(ohk.verify("good-host", 22,
                new Buffer.PlainBuffer(Base64.getDecoder()
                        .decode("AAAAC3NzaC1lZDI1NTE5AAAAIIRsJi92NJJTQwXHZiRiARoEy4n1jYsNTQePHFTSl7tG"))
                        .readPublicKey()));
    }

    @Test
    public void shouldMatchAnyHostFromMultiHostLine() throws Exception {
        File knownHosts = knownHosts(
                "schmizz.net,69.163.155.180 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6P9Hlwdahh250jGZYKg2snRq2j2lFJVdKSHyxqbJiVy9VX9gTkN3K2MD48qyrYLYOyGs3vTttyUk+cK++JMzURWsrP4piby7LpeOT+3Iq8CQNj4gXZdcH9w15Vuk2qS11at6IsQPVHpKD9HGg9//EFUccI/4w06k4XXLm/IxOGUwj6I2AeWmEOL3aDi+fe07TTosSdLUD6INtR0cyKsg0zC7Da24ixoShT8Oy3x2MpR7CY3PQ1pUVmvPkr79VeA+4qV9F1JM09WdboAMZgWQZ+XrbtuBlGsyhpUHSCQOya+kOJ+bYryS+U7A+6nmTW3C9FX4FgFqTF89UHOC7V0zZQ==");
        PublicKey k = new Buffer.PlainBuffer(Base64.getDecoder().decode(
                "AAAAB3NzaC1yc2EAAAABIwAAAQEA6P9Hlwdahh250jGZYKg2snRq2j2lFJVdKSHyxqbJiVy9VX9gTkN3K2MD48qyrYLYOyGs3vTttyUk+cK++JMzURWsrP4piby7LpeOT+3Iq8CQNj4gXZdcH9w15Vuk2qS11at6IsQPVHpKD9HGg9//EFUccI/4w06k4XXLm/IxOGUwj6I2AeWmEOL3aDi+fe07TTosSdLUD6INtR0cyKsg0zC7Da24ixoShT8Oy3x2MpR7CY3PQ1pUVmvPkr79VeA+4qV9F1JM09WdboAMZgWQZ+XrbtuBlGsyhpUHSCQOya+kOJ+bYryS+U7A+6nmTW3C9FX4FgFqTF89UHOC7V0zZQ=="))
                .readPublicKey();
        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);

        assertTrue(ohk.verify("schmizz.net", 22, k));
        assertTrue(ohk.verify("69.163.155.180", 22, k));
    }

    @ParameterizedTest
    @MethodSource("com.hierynomus.sshj.transport.verification.OpenSSHKnownHostsTest#commentedHostEntries")
    public void shouldRetainCommentAtEndOfLine(String entry, String comment) throws Exception {
        File knownHosts = knownHosts(entry);
        OpenSSHKnownHosts ohk = new OpenSSHKnownHosts(knownHosts);
        assertEquals(1, ohk.entries().size());
        assertThat(ohk.entries().get(0)).extracting("comment").isEqualTo(comment);
    }

    public static Stream<Arguments> commentedHostEntries() {
        return Stream.of(
            Arguments.of("|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6P9Hlwdahh250jGZYKg2snRq2j2lFJVdKSHyxqbJiVy9VX9gTkN3K2MD48qyrYLYOyGs3vTttyUk+cK++JMzURWsrP4piby7LpeOT+3Iq8CQNj4gXZdcH9w15Vuk2qS11at6IsQPVHpKD9HGg9//EFUccI/4w06k4XXLm/IxOGUwj6I2AeWmEOL3aDi+fe07TTosSdLUD6INtR0cyKsg0zC7Da24ixoShT8Oy3x2MpR7CY3PQ1pUVmvPkr79VeA+4qV9F1JM09WdboAMZgWQZ+XrbtuBlGsyhpUHSCQOya+kOJ+bYryS+U7A+6nmTW3C9FX4FgFqTF89UHOC7V0zZQ== this is a comment", "this is a comment"),
            Arguments.of("test.com,1.1.1.1 2048 35 22017496617994656680820635966392838863613340434802393112245951008866692373218840197754553998457793202561151141246686162285550121243768846314646395880632789308110750881198697743542374668273149584280424505890648953477691795864456749782348425425954366277600319096366690719901119774784695056100331902394094537054256611668966698242432417382422091372756244612839068092471592121759862971414741954991375710930168229171638843329213652899594987626853020377726482288618521941129157643483558764875338089684351824791983007780922947554898825663693324944982594850256042689880090306493029526546183035567296830604572253312294059766327 single",
                "single"),
            Arguments.of("schmizz.net,69.163.155.180 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6P9Hlwdahh250jGZYKg2snRq2j2lFJVdKSHyxqbJiVy9VX9gTkN3K2MD48qyrYLYOyGs3vTttyUk+cK++JMzURWsrP4piby7LpeOT+3Iq8CQNj4gXZdcH9w15Vuk2qS11at6IsQPVHpKD9HGg9//EFUccI/4w06k4XXLm/IxOGUwj6I2AeWmEOL3aDi+fe07TTosSdLUD6INtR0cyKsg0zC7Da24ixoShT8Oy3x2MpR7CY3PQ1pUVmvPkr79VeA+4qV9F1JM09WdboAMZgWQZ+XrbtuBlGsyhpUHSCQOya+kOJ+bYryS+U7A+6nmTW3C9FX4FgFqTF89UHOC7V0zZQ==", null),
            Arguments.of("schmizz.net,69.163.155.180 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6P9Hlwdahh250jGZYKg2snRq2j2lFJVdKSHyxqbJiVy9VX9gTkN3K2MD48qyrYLYOyGs3vTttyUk+cK++JMzURWsrP4piby7LpeOT+3Iq8CQNj4gXZdcH9w15Vuk2qS11at6IsQPVHpKD9HGg9//EFUccI/4w06k4XXLm/IxOGUwj6I2AeWmEOL3aDi+fe07TTosSdLUD6INtR0cyKsg0zC7Da24ixoShT8Oy3x2MpR7CY3PQ1pUVmvPkr79VeA+4qV9F1JM09WdboAMZgWQZ+XrbtuBlGsyhpUHSCQOya+kOJ+bYryS+U7A+6nmTW3C9FX4FgFqTF89UHOC7V0zZQ== ", null),
            Arguments.of("schmizz.net,69.163.155.180 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6P9Hlwdahh250jGZYKg2snRq2j2lFJVdKSHyxqbJiVy9VX9gTkN3K2MD48qyrYLYOyGs3vTttyUk+cK++JMzURWsrP4piby7LpeOT+3Iq8CQNj4gXZdcH9w15Vuk2qS11at6IsQPVHpKD9HGg9//EFUccI/4w06k4XXLm/IxOGUwj6I2AeWmEOL3aDi+fe07TTosSdLUD6INtR0cyKsg0zC7Da24ixoShT8Oy3x2MpR7CY3PQ1pUVmvPkr79VeA+4qV9F1JM09WdboAMZgWQZ+XrbtuBlGsyhpUHSCQOya+kOJ+bYryS+U7A+6nmTW3C9FX4FgFqTF89UHOC7V0zZQ== extra   space", "extra   space")
        );
    }

    private File knownHosts(String contents) throws IOException {
        File knownHosts = new File(tempDir, "known_hosts");
        Files.write(knownHosts.toPath(), contents.getBytes(StandardCharsets.UTF_8));
        return knownHosts;
    }
}
