package com.km.ids.analyser.snort.port;

public class SnortPortSingle extends SnortPort {
    private final int port;
    private final boolean isNot;

    public SnortPortSingle(int port, boolean isNot) {
        super();
        this.port = port;
        this.isNot = isNot;
    }

    @Override
    public String toString() {
        return "SnortPortSingle{" +
                "port=" + port +
                ", isNot=" + isNot +
                '}';
    }


    @Override
    public boolean matches(int packetPort) {
        boolean matches = port == packetPort;
        if (isNot) {
            return !matches;
        }
        return matches;
    }
}
