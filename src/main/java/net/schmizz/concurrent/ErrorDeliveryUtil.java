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
 */
package net.schmizz.concurrent;

import java.util.Collection;

public class ErrorDeliveryUtil {

    public static void alertPromises(Throwable x, Promise... promises) {
        for (Promise p : promises)
            p.deliverError(x);
    }

    public static void alertPromises(Throwable x, Collection<? extends Promise> promises) {
        for (Promise p : promises)
            p.deliverError(x);
    }

    public static void alertEvents(Throwable x, Event... events) {
        for (Event e : events)
            e.deliverError(x);
    }

    public static void alertEvents(Throwable x, Collection<? extends Event> events) {
        for (Event e : events)
            e.deliverError(x);
    }

}
