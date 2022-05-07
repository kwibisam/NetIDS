package side.snort;

public enum SnortProtocol {
    icmpv4,
    tcp,
    all,
    udp,
    dns,
    arp,
    igmp,
    unknown,
    sctp,
    ethernet,
    ip;

    public static SnortProtocol from(String protocol) {
        if (protocol == null) {
            return SnortProtocol.unknown;
        }
        try {
            return SnortProtocol.valueOf(protocol);
        } catch (IllegalArgumentException e) {
            SnortParser.logger.warn("Unknown snort protocol " + protocol);
            return SnortProtocol.unknown;
        }
    }
}
