package com.km.ids.analyser.snort.port;

public class SnortPortAny extends SnortPort {
    private boolean isNot;

    public SnortPortAny(boolean isNot) {
        super();
        this.isNot = isNot;
    }

    @Override
    public String toString() {
        return "SnortPortAny{" +
                "isNot=" + isNot +
                '}';
    }

    @Override
    public boolean matches(int packetPort) {
        return !isNot;
    }
}
