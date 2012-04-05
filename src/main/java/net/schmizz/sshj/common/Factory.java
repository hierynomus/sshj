/*
 * Copyright 2010-2012 sshj contributors
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
 *
 * This file may incorporate work covered by the following copyright and
 * permission notice:
 *
 *     Licensed to the Apache Software Foundation (ASF) under one
 *     or more contributor license agreements.  See the NOTICE file
 *     distributed with this work for additional information
 *     regarding copyright ownership.  The ASF licenses this file
 *     to you under the Apache License, Version 2.0 (the
 *     "License"); you may not use this file except in compliance
 *     with the License.  You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing,
 *      software distributed under the License is distributed on an
 *      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *      KIND, either express or implied.  See the License for the
 *      specific language governing permissions and limitations
 *      under the License.
 */
package net.schmizz.sshj.common;

import java.util.LinkedList;
import java.util.List;

/**
 * A basic factory interface.
 *
 * @param <T> the type of object created by this factory
 */
public interface Factory<T> {

    /**
     * Inteface for a named factory. Named factories are simply factories that are identified by a name. Such names are
     * used mainly in SSH algorithm negotiation.
     *
     * @param <T> type of object created by this factory
     */
    interface Named<T>
            extends Factory<T> {

        /** Utility functions */
        public static class Util {

            /**
             * Creates an object by picking a factory from {@code factories} that is identified by {@code name} from a
             * list of named {@code factories}. Uses the first match.
             *
             * @param factories list of available factories
             * @param name      name of the desired factory
             * @param <T>       type of the {@code factories}
             *
             * @return a newly created instance of {@code T} or {@code null} if there was no match
             */
            public static <T> T create(List<Named<T>> factories, String name) {
                if (factories != null)
                    for (Named<T> f : factories)
                        if (f.getName().equals(name))
                            return f.create();
                return null;
            }

            /**
             * Retrieve a particular factory as identified by {@code name} from a list of named {@code factories}.
             * Returns the first match.
             *
             * @param factories list of factories
             * @param name      the name of the factory to retrieve
             * @param <T>       type of the {@code factories}
             *
             * @return a factory or {@code null} if there was no match
             */
            public static <T> Named<T> get(List<Named<T>> factories, String name) {
                for (Named<T> f : factories)
                    if (f.getName().equals(name))
                        return f;
                return null;
            }

            /**
             * Get a comma-delimited string containing the factory names from the given list of {@code factories}.
             *
             * @param factories list of available factories
             * @param <T>       type of the {@code factories}
             *
             * @return a comma separated list of factory names
             */
            public static <T> List<String> getNames(List<Named<T>> factories) {
                List<String> list = new LinkedList<String>();
                for (Named<T> f : factories)
                    list.add(f.getName());
                return list;
            }

        }

        /** @return the name of this factory. */
        String getName();

    }

    /** @return a new object created using this factory. */
    T create();

}
