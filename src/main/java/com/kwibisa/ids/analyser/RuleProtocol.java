package com.kwibisa.ids.analyser;

public enum RuleProtocol {
    icmpv4,
    tcp,
    udp,
    dns,
    arp,
    unknown,
    ip;

    public static RuleProtocol from(String protocol) {
        if (protocol == null) {
            return RuleProtocol.unknown;
        }
        try {
            return RuleProtocol.valueOf(protocol);
        } 
        catch (IllegalArgumentException e) {
            return RuleProtocol.unknown;
        }
    }
}
