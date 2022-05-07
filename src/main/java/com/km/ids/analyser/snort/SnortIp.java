package com.km.ids.analyser.snort;

import com.km.ids.analyser.snort.address.SnortAddress;
import com.km.ids.analyser.snort.port.SnortPort;

import java.net.InetAddress;

public class SnortIp {
    private final SnortAddress address;
    private final SnortPort port;

    public SnortIp(String snort) throws Exception {
        String[] parts = snort.split("\\s");
        if (parts.length == 1) {
            this.address = SnortAddress.of(parts[0]);
            this.port = SnortPort.of("any");
        } else if (parts.length == 2) {
            this.address = SnortAddress.of(parts[0]);
            this.port = SnortPort.of(parts[1]);
        } else {
            throw new Exception("Malformed address " + snort);
        }
    }

    @Override
    public String toString() {
        return "SnortIp{" +
                "address='" + address + '\'' +
                ", port='" + port + '\'' +
                '}';
    }

    public boolean matches(InetAddress packetAddr, int packetPort) throws Exception {
        if (!port.matches(packetPort)) {
            return false;
        }
        return address.matches(packetAddr);
    }
}
