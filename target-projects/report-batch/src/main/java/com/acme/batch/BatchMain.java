package com.acme.batch;

import java.io.InputStream;
import java.util.Properties;

/** Nightly report job. Loads its import plugin by name from plugins.properties. */
public class BatchMain {

    public static void main(String[] args) throws Exception {
        String requested = args.length > 0 ? args[0] : "../reports/2026/q3.csv";
        String safePath = PathSanitizer.clean(requested);

        Properties config = new Properties();
        try (InputStream in = BatchMain.class.getResourceAsStream("/plugins.properties")) {
            if (in != null) {
                config.load(in);
            }
        }
        // The plugin class is chosen at runtime, so static analysis cannot see which code runs.
        String pluginClass = config.getProperty("import.plugin");
        Object plugin = Class.forName(pluginClass).getDeclaredConstructor().newInstance();
        Object result = plugin.getClass().getMethod("run", String.class).invoke(plugin, "<list/>");

        System.out.println(safePath + " -> " + result);
    }
}
