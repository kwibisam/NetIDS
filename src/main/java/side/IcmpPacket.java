package side;

import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.Packet;

/**
 * @author clerc
 * @since 2020/04/13
 */
public class IcmpPacket extends AbstractPacket {
    private final Packet corePacket;

    public IcmpPacket(Packet corePacket) {
        super();
        this.corePacket = corePacket;
    }

    @Override
    public Builder getBuilder() {
        return corePacket.getBuilder();
    }

    public Integer getType() {
        if (corePacket instanceof IcmpV4CommonPacket) {
            return (int) ((IcmpV4CommonPacket) corePacket).getHeader().getType().value();
        }
        if (corePacket instanceof IcmpV6CommonPacket) {
            return (int) ((IcmpV6CommonPacket) corePacket).getHeader().getType().value();
        }
        return null;
    }

    public Integer getCode() {
        if (corePacket instanceof IcmpV4CommonPacket) {
            return (int) ((IcmpV4CommonPacket) corePacket).getHeader().getCode().value();
        }
        if (corePacket instanceof IcmpV6CommonPacket) {
            return (int) ((IcmpV6CommonPacket) corePacket).getHeader().getCode().value();
        }
        return null;
    }
}
