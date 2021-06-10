package com.server.avast.verisign.utils;

import org.junit.Test;
import org.springframework.util.AntPathMatcher;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Vitasek L.
 */
public class MatcherTest {

    @Test
    public void matcherTest() {
        final AntPathMatcher matcher = new AntPathMatcher("/");
        final String pattern = "**/{name:[a-zA-Z][a-zA-Z0-9_.-]*}-{version:[0-9]+(\\.[0-9a-zA-Z]+)+}-release.arch.rpm";
        final boolean match = matcher.match(pattern, "com/avast/google/mojeapka-1.0.0-release.arch.rpm");
        assertTrue(match);

        final boolean match2 = matcher.match(pattern, "com/avast/google/ff_hdfs-shell-6.6.51-1.prod.noarch.rpm");
        assertFalse(match2);
    }

}
