package com.acme.batch;

import org.apache.commons.io.FilenameUtils;

/**
 * Normalises report paths supplied by users.
 * (The old scheduler used commons-collections; it has since been removed from the code.)
 */
public final class PathSanitizer {

    private PathSanitizer() {
    }

    public static String clean(String userPath) {
        // Vulnerable call: FilenameUtils.normalize can be tricked by crafted paths.
        return FilenameUtils.normalize(userPath);
    }
}
