package com.km.ids.analyser.snort.port;

import java.util.List;

/**
 * @author clerc
 * @since 2020/04/13
 */
public class SnortPortComplex extends SnortPort {
    private List<SnortPort> sub;

    public SnortPortComplex(List<SnortPort> sub) {
        this.sub = sub;
    }

    @Override
    public boolean matches(int packetPort) {
        for (SnortPort matcher : sub) {
            if (matcher.matches(packetPort)) {
                return true;
            }
        }
        return false;
    }
}
