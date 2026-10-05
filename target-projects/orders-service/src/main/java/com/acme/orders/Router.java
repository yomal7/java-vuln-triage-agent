package com.acme.orders;

import org.springframework.util.AntPathMatcher;

/** Maps request paths to handlers. The path comes from the client. */
public class Router {

    private final AntPathMatcher matcher = new AntPathMatcher();

    public String route(String requestPath) {
        // Vulnerable call: AntPathMatcher.match with a client-controlled path.
        if (matcher.match("/orders/**", requestPath)) {
            return "orders-handler";
        }
        return "not-found";
    }
}
