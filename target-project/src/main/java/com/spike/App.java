package com.spike;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Deliberately tiny. Only log4j-core is actually called from source here.
 * jackson-databind, spring-core, and commons-collections are on the
 * classpath but unused in this file on purpose — the triage agent should
 * be able to notice that difference when it checks code usage.
 */
public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        logger.info("vuln-triage-target running");
    }
}
