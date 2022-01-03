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
package com.hierynomus.sshj.common.codec;

/**
 * Base64 Decoder abstracts access to implementation classes
 */
public interface Base64Decoder {
    /**
     * Decode Base64 string to byte array
     *
     * @param encoded Base64 encoded string
     * @return byte array
     */
    byte[] decode(String encoded);
}
