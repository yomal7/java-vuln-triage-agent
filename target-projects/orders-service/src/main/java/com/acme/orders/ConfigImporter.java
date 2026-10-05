package com.acme.orders;

import org.yaml.snakeyaml.Yaml;

/** Imports a configuration document uploaded by an administrator. */
public class ConfigImporter {

    public Object importConfig(String yamlText) {
        // Vulnerable call: Yaml.load with the default constructor accepts arbitrary types.
        return new Yaml().load(yamlText);
    }
}
