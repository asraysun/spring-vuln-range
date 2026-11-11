package com.example.vulnrange.m06.vuln;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Records every time <em>attacker-supplied</em> bytes caused application code to run.
 * Read it with {@code GET /vuln6/side-effects} to make the invisible primitive visible.
 */
public final class SideEffects {

    private static final List<String> LOG = Collections.synchronizedList(new ArrayList<>());

    private SideEffects() {
    }

    public static void record(String what) {
        LOG.add(what);
    }

    public static List<String> log() {
        synchronized (LOG) {
            return List.copyOf(LOG);
        }
    }

    public static int count() {
        return LOG.size();
    }

    public static void clear() {
        LOG.clear();
    }
}
