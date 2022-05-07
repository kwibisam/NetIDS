package com.km.ids.analyser.utils;

import java.net.InetAddress;
import java.util.Objects;

/**
 *
 * @author Kwibisa Mwene
 */

public class Connection {
    private final InetAddress add1;
    private final InetAddress add2;
    private final int port1;
    private final int port2;

    public Connection(InetAddress add1, int port1, InetAddress add2, int port2) {
        this.add1 = add1;
        this.port1 = port1;
        this.add2 = add2;
        this.port2 = port2;
    }

    @Override
    public String toString() {
        return "Tuple{" +
                add1 + ":" + port1 + "<>" +
                add2 + ":" + port2 + "<>" +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Connection other = (Connection) o;
        return (Objects.equals(add1, other.add1) && port1 == other.port1 && Objects.equals(add2, other.add2) && port2 == other.port2) ||
                (Objects.equals(add1, other.add2) && port1 == other.port2 && Objects.equals(add2, other.add1) && port2 == other.port1);
    }

    @Override
    public int hashCode() {
        int a = Objects.hash(add1);
        int b = Objects.hash(add2);
        if (a < b) {
            return Objects.hash(add1, port1, add2, port2);
        } else {
            return Objects.hash(add2, port2, add1, port1);
        }
    }
}
