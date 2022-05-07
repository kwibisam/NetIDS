package com.km.ids.analyser.snort.address;

import java.net.InetAddress;

public class SnortAddressIpV4 extends SnortAddress {
    private final String ip;
    private final boolean isNot;

    public SnortAddressIpV4(String ip, boolean isNot) {
        super();
        this.ip = ip;
        this.isNot = isNot;
    }

    @Override
    public String toString() {
        return "SnortAddressIpV4{" +
                "ip='" + ip + '\'' +
                ", isNot=" + isNot +
                '}';
    }

    @Override
    public boolean matches(InetAddress packetAddr) {
        boolean match = packetAddr.getHostAddress().equals(ip);
        if (isNot) {
            return !match;
        }
        return match;
    }
}
