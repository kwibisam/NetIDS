package com.km.ids.analyser.snort.address;

import com.km.ids.analyser.snort.Variables;

import java.net.InetAddress;
import java.util.Locale;

public abstract class SnortAddress {
    public static SnortAddress of(String value) throws Exception {
        String s = value;
        boolean isNot = false;
        while (s.startsWith("!")) {
            isNot = !isNot;
            s = s.substring(1);
        }

        String lower = s.toLowerCase(Locale.ENGLISH);
        if ("any".equals(lower)) {
            return new SnortAddressAny(isNot);
        }
        if (s.contains("/")) {
            String[] parts = s.split("/", 2);
            if (!parts[0].matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(\\.\\d{1,3})?$")) {
                throw new Exception("Invalid IP address " + parts[0] + " in " + value);
            }
            try {
                int mask = Integer.parseInt(parts[1]);
                String ip = parts[0];
                while (ip.split("\\.").length < 4) {
                    ip = ip + ".0";
                }
                return new SnortAddressNetwork(ip, mask, isNot);
            } catch (NumberFormatException e) {
                throw new Exception("Invalid IP mask " + parts[1] + " in " + value, e);
            }
        }
        if (s.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            return new SnortAddressIpV4(s, isNot);
        }

        if(Variables.isVariable(s)){
            String prefix="";
            if(isNot){
                prefix="!";
            }
            return of(prefix+Variables.resolve(s));
        }

        throw new Exception("Unknown address syntax " + s);
    }

    public abstract boolean matches(InetAddress packetAddr) throws Exception;
}
