package com.acme.orders;

import java.util.Map;
import org.apache.commons.text.StringSubstitutor;

/** Builds customer notification text from a template. */
public class NotificationFormatter {

    public String format(String template, Map<String, String> values) {
        String withValues = new StringSubstitutor(values).replace(template);
        // Vulnerable call: the default interpolator evaluates ${script:...}, ${dns:...}, ${url:...}.
        return StringSubstitutor.createInterpolator().replace(withValues);
    }
}
