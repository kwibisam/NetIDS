package com.km.ids.analyser.snort.port;

import java.util.List;

public class SnortPortList extends SnortPort {
    private final List<Integer> ports;
    private final boolean isNot;

    public SnortPortList(List<Integer> ports, boolean isNot) {
        super();
        this.ports = ports;
        this.isNot = isNot;
    }

    @Override
    public String toString() {
        return "SnortPortList{" +
                "ports=" + ports +
                ", isNot=" + isNot +
                '}';
    }

    @Override
    public boolean matches(int packetPort) {
        boolean matches = ports.contains(packetPort);
        if (isNot) {
            return !matches;
        }
        return matches;
    }
}
