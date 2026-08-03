package com.ourgiant.passman.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UpdateCheckerTest {

    @Test
    void detectsNewerPatchVersion() {
        assertTrue(UpdateChecker.isNewerVersion("1.2.1", "1.2.0"));
    }

    @Test
    void detectsNewerMinorVersion() {
        assertTrue(UpdateChecker.isNewerVersion("1.3.0", "1.2.9"));
    }

    @Test
    void detectsNewerMajorVersion() {
        assertTrue(UpdateChecker.isNewerVersion("2.0.0", "1.9.9"));
    }

    @Test
    void equalVersionsAreNotNewer() {
        assertFalse(UpdateChecker.isNewerVersion("1.2.0", "1.2.0"));
    }

    @Test
    void olderVersionIsNotNewer() {
        assertFalse(UpdateChecker.isNewerVersion("1.1.0", "1.2.0"));
    }

    @Test
    void differingSegmentCountsAreHandled() {
        assertTrue(UpdateChecker.isNewerVersion("1.2.1.0", "1.2"));
        assertFalse(UpdateChecker.isNewerVersion("1.2", "1.2.0.1"));
    }

    @Test
    void nonNumericSegmentsAreTreatedAsNotNewerRatherThanThrowing() {
        // Every segment before the malformed one must be equal, or an earlier segment decides
        // the comparison via short-circuit before the malformed one is ever parsed -- these two
        // both require reaching the bad segment.
        assertFalse(UpdateChecker.isNewerVersion("0.1.0", "0.1.0-SNAPSHOT"));
        assertFalse(UpdateChecker.isNewerVersion("1.1.0-rc1", "1.1.0"));
    }
}
