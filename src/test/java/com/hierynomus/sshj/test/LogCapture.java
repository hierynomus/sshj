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
package com.hierynomus.sshj.test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * Captures logback logging events emitted under a given logger so tests can assert on them.
 * Attach with {@link #attachTo(String)} and always {@link #close()} it (use try-with-resources).
 */
public class LogCapture extends AppenderBase<ILoggingEvent> implements AutoCloseable {

    private final List<ILoggingEvent> events = new CopyOnWriteArrayList<>();
    private final Logger logger;

    private LogCapture(Logger logger) {
        this.logger = logger;
        setName("test-log-capture");
    }

    public static LogCapture attachTo(String loggerName) {
        LogCapture capture = new LogCapture((Logger) LoggerFactory.getLogger(loggerName));
        capture.start();
        capture.logger.addAppender(capture);
        return capture;
    }

    @Override
    protected void append(ILoggingEvent event) {
        event.prepareForDeferredProcessing();
        events.add(event);
    }

    public List<ILoggingEvent> events() {
        return new ArrayList<>(events);
    }

    /** ERROR-level events, optionally restricted to the given logger classes. */
    public List<ILoggingEvent> errorsFrom(Class<?>... loggers) {
        Set<String> names = Arrays.stream(loggers).map(Class::getName).collect(Collectors.toSet());
        return events().stream()
                .filter(e -> e.getLevel() == Level.ERROR)
                .filter(e -> names.isEmpty() || names.contains(e.getLoggerName()))
                .collect(Collectors.toList());
    }

    @Override
    public void close() {
        logger.detachAppender(this);
        stop();
    }
}
