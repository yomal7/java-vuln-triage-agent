package com.acme.batch.plugins;

import com.thoughtworks.xstream.XStream;

/** Import plugin, loaded by name at runtime (see plugins.properties). */
public class XmlImportPlugin {

    public Object run(String xml) {
        // Vulnerable call: XStream.fromXML deserialises attacker-controlled XML.
        XStream xstream = new XStream();
        return xstream.fromXML(xml);
    }
}
