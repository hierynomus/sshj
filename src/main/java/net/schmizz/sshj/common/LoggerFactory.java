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
package net.schmizz.sshj.common;

import org.slf4j.Logger;

public interface LoggerFactory {
    Logger getLogger(String name);
    Logger getLogger(Class<?> clazz);

    /**
     * Default SLF4J-based implementation of the SSHJ LoggerFactory.
     */
    LoggerFactory DEFAULT = new LoggerFactory() {
        @Override
        public Logger getLogger(String name) {
            return org.slf4j.LoggerFactory.getLogger(name);
        }

        @Override
        public Logger getLogger(Class<?> clazz) {
            return org.slf4j.LoggerFactory.getLogger(clazz);
        }
    };
}
