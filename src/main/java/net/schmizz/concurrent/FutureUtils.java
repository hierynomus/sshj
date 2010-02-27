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
package net.schmizz.concurrent;

import java.util.Collection;

public class FutureUtils {

    public static void alertAll(Exception x, Future... futures) {
        for (Future f : futures)
            f.error(x);
    }

    public static void alertAll(Exception x, Collection<? extends Future> futures) {
        for (Future f : futures)
            f.error(x);
    }

}
